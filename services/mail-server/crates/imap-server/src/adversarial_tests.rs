//! Adversarial end-to-end tests for the IMAP4rev1 server.
//!
//! Everything here drives the REAL command dispatch (`serve` / `handle_command`
//! and the parsers beneath) over an in-memory `tokio::io::duplex` stream, with
//! a programmable in-memory implementation of the mailstore gRPC service
//! mounted on the SAME in-memory transport (tonic's `DuplexStream` support).
//! No TCP sockets and no TLS handshakes are involved.

use super::*;
use mail_proto::mailstore_service_server::{MailstoreService, MailstoreServiceServer};
use std::pin::Pin;
use std::sync::Mutex as StdMutex;
use std::task::{Context as TaskContext, Poll};
use tokio::io::DuplexStream;
use tokio::sync::mpsc;

// ── programmable in-memory mailstore ────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct MockMailstore {
    state: Arc<StdMutex<MockState>>,
}

#[derive(Default)]
struct MockState {
    /// email (lowercase) -> (account_id, password)
    accounts: HashMap<String, (String, String)>,
    /// account_id -> mailbox name (lowercase) -> row
    mailboxes: HashMap<String, HashMap<String, mail_proto::Mailbox>>,
    /// account_id -> mailbox name (lowercase) -> messages (ascending uid)
    messages: HashMap<String, HashMap<String, Vec<mail_proto::MessageMeta>>>,
    /// (account, mailbox, uid) -> raw body
    bodies: HashMap<(String, String, u64), Vec<u8>>,
    /// account|mailbox -> event stream sender (IDLE)
    events: HashMap<String, mpsc::UnboundedSender<MailboxEvent>>,
    /// UIDs the mock search returns for `header:` queries.
    header_hits: HashSet<u64>,
    /// Method names that must fail with `Status::unavailable`.
    fail: HashSet<String>,
    /// Recorded mutating calls: (method, detail).
    calls: Vec<(String, String)>,
}

impl MockMailstore {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(StdMutex::new(MockState::default())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().expect("mock state mutex poisoned")
    }

    pub(crate) fn fail(&self, method: &str) {
        self.lock().fail.insert(method.to_string());
    }

    pub(crate) fn add_account(&self, email: &str, account_id: &str, password: &str) {
        self.lock().accounts.insert(
            email.to_lowercase(),
            (account_id.to_string(), password.to_string()),
        );
    }

    /// Overwrite a stored mailbox row (attributes / delimiter) for tests that
    /// need non-default LIST/LSUB shapes.
    pub(crate) fn set_mailbox_row(&self, account: &str, row: mail_proto::Mailbox) {
        self.lock()
            .mailboxes
            .entry(account.to_string())
            .or_default()
            .insert(row.name.to_lowercase(), row);
    }

    pub(crate) fn add_mailbox(&self, account: &str, name: &str, uidvalidity: u64) {
        let mut g = self.lock();
        g.mailboxes.entry(account.to_string()).or_default().insert(
            name.to_lowercase(),
            mail_proto::Mailbox {
                name: name.to_string(),
                delimiter: "/".to_string(),
                attributes: Vec::new(),
                uidvalidity,
                uidnext: 1,
                exists: 0,
                recent: 0,
                unseen: 0,
            },
        );
    }

    /// Append one message and return its UID.
    pub(crate) fn add_message(
        &self,
        account: &str,
        mailbox: &str,
        subject: &str,
        from: &str,
        flags: mail_proto::MessageFlags,
        internal_date: i64,
    ) -> u64 {
        let seen = flags.seen;
        let mut g = self.lock();
        let row = g
            .mailboxes
            .entry(account.to_string())
            .or_default()
            .entry(mailbox.to_lowercase())
            .or_insert_with(|| mail_proto::Mailbox {
                name: mailbox.to_string(),
                delimiter: "/".to_string(),
                uidvalidity: 1,
                uidnext: 1,
                ..Default::default()
            });
        let uid = row.uidnext;
        row.uidnext += 1;
        row.exists += 1;
        if !seen {
            row.unseen += 1;
        }
        let meta = mail_proto::MessageMeta {
            id: format!("msg-{uid}"),
            account_id: account.to_string(),
            mailbox: mailbox.to_string(),
            uid,
            blob_hash: format!("blob-{uid}"),
            size: 100,
            envelope: Some(mail_proto::EmailEnvelope {
                from: from.to_string(),
                to: vec!["rcpt@example.test".to_string()],
                subject: subject.to_string(),
                message_id: format!("<{uid}@example.test>"),
                date: internal_date,
                ..Default::default()
            }),
            flags: Some(flags),
            internal_date,
        };
        g.messages
            .entry(account.to_string())
            .or_default()
            .entry(mailbox.to_lowercase())
            .or_default()
            .push(meta);
        uid
    }

    pub(crate) fn set_body(&self, account: &str, mailbox: &str, uid: u64, body: &[u8]) {
        self.lock().bodies.insert(
            (account.to_string(), mailbox.to_lowercase(), uid),
            body.to_vec(),
        );
    }

    /// Same as [`Self::add_message`] but with explicit to/cc/bcc envelope
    /// recipients, so SEARCH TO/CC/BCC criteria can be driven adversarially.
    pub(crate) fn add_message_with_recipients(
        &self,
        account: &str,
        mailbox: &str,
        recipients: (&[&str], &[&str], &[&str]),
        flags: mail_proto::MessageFlags,
        internal_date: i64,
    ) -> u64 {
        let uid = self.add_message(
            account,
            mailbox,
            "subj",
            "from@example.test",
            flags,
            internal_date,
        );
        let (to, cc, bcc) = recipients;
        let mut g = self.lock();
        if let Some(meta) = g
            .messages
            .get_mut(account)
            .and_then(|m| m.get_mut(&mailbox.to_lowercase()))
            .and_then(|v| v.last_mut())
        {
            let env = meta.envelope.get_or_insert_with(Default::default);
            env.to = to.iter().map(|s| s.to_string()).collect();
            env.cc = cc.iter().map(|s| s.to_string()).collect();
            env.bcc = bcc.iter().map(|s| s.to_string()).collect();
        }
        uid
    }

    pub(crate) fn events_sender(
        &self,
        account: &str,
        mailbox: &str,
    ) -> mpsc::UnboundedSender<MailboxEvent> {
        let key = format!("{account}|{}", mailbox.to_lowercase());
        let mut g = self.lock();
        g.events
            .entry(key)
            .or_insert_with(|| mpsc::unbounded_channel().0)
            .clone()
    }

    pub(crate) fn recorded(&self, method: &str) -> Vec<String> {
        self.lock()
            .calls
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, detail)| detail.clone())
            .collect()
    }

    pub(crate) fn message_uids(&self, account: &str, mailbox: &str) -> Vec<u64> {
        self.lock()
            .messages
            .get(account)
            .and_then(|m| m.get(&mailbox.to_lowercase()))
            .map(|v| v.iter().map(|m| m.uid).collect())
            .unwrap_or_default()
    }

    pub(crate) fn mailbox_row(&self, account: &str, mailbox: &str) -> Option<mail_proto::Mailbox> {
        self.lock()
            .mailboxes
            .get(account)
            .and_then(|m| m.get(&mailbox.to_lowercase()))
            .cloned()
    }
}

/// Stream adapter for the IDLE event feed (same trait tokio_stream re-exports).
pub(crate) struct MockEventStream(mpsc::UnboundedReceiver<MailboxEvent>);

impl futures::Stream for MockEventStream {
    type Item = Result<MailboxEvent, tonic::Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().0.poll_recv(cx).map(|item| item.map(Ok))
    }
}

#[tonic::async_trait]
impl MailstoreService for MockMailstore {
    type SubscribeMailboxStream = MockEventStream;

    async fn store_message(
        &self,
        request: tonic::Request<mail_proto::StoreMessageRequest>,
    ) -> Result<tonic::Response<mail_proto::StoreMessageResponse>, tonic::Status> {
        let req = request.into_inner();
        {
            let g = self.lock();
            if g.fail.contains("store_message") {
                return Err(tonic::Status::unavailable("mock store_message failure"));
            }
        }
        let mut g = self.lock();
        if g.fail.contains("quota") {
            return Err(tonic::Status::resource_exhausted("quota exceeded"));
        }
        let row = g
            .mailboxes
            .entry(req.account_id.clone())
            .or_default()
            .get_mut(&req.mailbox.to_lowercase())
            .ok_or_else(|| tonic::Status::not_found("no such mailbox"))?;
        let uid = row.uidnext;
        row.uidnext += 1;
        row.exists += 1;
        let flags = req.flags.clone().unwrap_or_default();
        if !flags.seen {
            row.unseen += 1;
        }
        let meta = mail_proto::MessageMeta {
            id: format!("appended-{uid}"),
            account_id: req.account_id.clone(),
            mailbox: req.mailbox.clone(),
            uid,
            blob_hash: format!("blob-{uid}"),
            size: req.raw_message.len() as u64,
            envelope: Some(mail_proto::EmailEnvelope {
                subject: "appended".to_string(),
                ..Default::default()
            }),
            flags: Some(flags),
            internal_date: req.internal_date,
        };
        g.messages
            .entry(req.account_id.clone())
            .or_default()
            .entry(req.mailbox.to_lowercase())
            .or_default()
            .push(meta);
        g.bodies.insert(
            (req.account_id.clone(), req.mailbox.to_lowercase(), uid),
            req.raw_message.to_vec(),
        );
        g.calls.push((
            "store_message".to_string(),
            format!("{}|{}|{}", req.account_id, req.mailbox, uid),
        ));
        Ok(tonic::Response::new(mail_proto::StoreMessageResponse {
            message_id: format!("appended-{uid}"),
            uid,
            blob_hash: format!("blob-{uid}"),
        }))
    }

    async fn get_message(
        &self,
        request: tonic::Request<mail_proto::GetMessageRequest>,
    ) -> Result<tonic::Response<mail_proto::GetMessageResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("get_message") {
            return Err(tonic::Status::unavailable("mock get_message failure"));
        }
        if g.fail.contains("get_message_busy") {
            return Err(tonic::Status::resource_exhausted("mock busy"));
        }
        let meta = g
            .messages
            .get(&req.account_id)
            .and_then(|m| m.get(&req.mailbox.to_lowercase()))
            .and_then(|v| v.iter().find(|m| m.uid == req.uid))
            .cloned()
            .ok_or_else(|| tonic::Status::not_found("no such message"))?;
        let body = if req.include_body {
            g.bodies
                .get(&(req.account_id.clone(), req.mailbox.to_lowercase(), req.uid))
                .cloned()
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(tonic::Response::new(mail_proto::GetMessageResponse {
            meta: Some(meta),
            body,
        }))
    }

    async fn list_messages(
        &self,
        request: tonic::Request<mail_proto::ListMessagesRequest>,
    ) -> Result<tonic::Response<mail_proto::ListMessagesResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("list_messages") {
            return Err(tonic::Status::unavailable("mock list_messages failure"));
        }
        let mut messages: Vec<mail_proto::MessageMeta> = g
            .messages
            .get(&req.account_id)
            .and_then(|m| m.get(&req.mailbox.to_lowercase()))
            .cloned()
            .unwrap_or_default();
        messages.retain(|m| m.uid >= req.uid_min && m.uid <= req.uid_max);
        messages.sort_by_key(|m| m.uid);
        if req.limit > 0 {
            messages.truncate(req.limit as usize);
        }
        Ok(tonic::Response::new(mail_proto::ListMessagesResponse {
            messages,
        }))
    }

    async fn search_messages(
        &self,
        request: tonic::Request<mail_proto::SearchMessagesRequest>,
    ) -> Result<tonic::Response<mail_proto::SearchMessagesResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("search_messages") {
            return Err(tonic::Status::unavailable("mock search_messages failure"));
        }
        let mut messages: Vec<mail_proto::MessageMeta> = g
            .messages
            .get(&req.account_id)
            .and_then(|m| m.get(&req.mailbox.to_lowercase()))
            .cloned()
            .unwrap_or_default();
        if let Some((field, value)) = req.query.split_once('\u{1}') {
            // headers-JSONB convention: honour the recorded hits, and mimic
            // the store by matching only messages whose header value matches.
            let _ = field;
            let needle = value.to_lowercase();
            messages.retain(|m| {
                g.header_hits.contains(&m.uid)
                    || m.envelope
                        .as_ref()
                        .map(|e| e.subject.to_lowercase().contains(&needle))
                        .unwrap_or(false)
            });
        } else {
            let needle = req.query.to_lowercase();
            messages.retain(|m| {
                m.envelope
                    .as_ref()
                    .map(|e| {
                        e.subject.to_lowercase().contains(&needle)
                            || e.from.to_lowercase().contains(&needle)
                    })
                    .unwrap_or(false)
            });
        }
        let total = messages.len() as i32;
        Ok(tonic::Response::new(mail_proto::SearchMessagesResponse {
            messages,
            total,
        }))
    }

    async fn set_flags(
        &self,
        request: tonic::Request<mail_proto::SetFlagsRequest>,
    ) -> Result<tonic::Response<mail_proto::SetFlagsResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("set_flags") {
            return Err(tonic::Status::unavailable("mock set_flags failure"));
        }
        let op = mail_proto::FlagOperation::try_from(req.operation)
            .unwrap_or(mail_proto::FlagOperation::Unspecified);
        let flags = req.flags.clone().unwrap_or_default();
        g.calls.push((
            "set_flags".to_string(),
            format!("{:?}|{:?}|{}", op, req.uids, req.account_id),
        ));
        let bucket = g
            .messages
            .entry(req.account_id.clone())
            .or_default()
            .entry(req.mailbox.to_lowercase())
            .or_default();
        let mut updated = 0u32;
        for meta in bucket.iter_mut() {
            if !req.uids.contains(&meta.uid) {
                continue;
            }
            let mut f = meta.flags.clone().unwrap_or_default();
            match op {
                mail_proto::FlagOperation::Set => f = flags.clone(),
                mail_proto::FlagOperation::Add => {
                    f.seen |= flags.seen;
                    f.answered |= flags.answered;
                    f.flagged |= flags.flagged;
                    f.deleted |= flags.deleted;
                    f.draft |= flags.draft;
                    for kw in &flags.custom {
                        if !f.custom.contains(kw) {
                            f.custom.push(kw.clone());
                        }
                    }
                }
                mail_proto::FlagOperation::Remove => {
                    f.seen &= !flags.seen;
                    f.answered &= !flags.answered;
                    f.flagged &= !flags.flagged;
                    f.deleted &= !flags.deleted;
                    f.draft &= !flags.draft;
                    f.custom.retain(|kw| !flags.custom.contains(kw));
                }
                mail_proto::FlagOperation::Unspecified => {}
            }
            meta.flags = Some(f);
            updated += 1;
        }
        Ok(tonic::Response::new(mail_proto::SetFlagsResponse {
            updated_count: updated,
        }))
    }

    async fn get_flags(
        &self,
        request: tonic::Request<mail_proto::GetFlagsRequest>,
    ) -> Result<tonic::Response<mail_proto::GetFlagsResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("get_flags") {
            return Err(tonic::Status::unavailable("mock get_flags failure"));
        }
        let mut flags = HashMap::new();
        if let Some(bucket) = g
            .messages
            .get(&req.account_id)
            .and_then(|m| m.get(&req.mailbox.to_lowercase()))
        {
            for meta in bucket {
                flags.insert(meta.uid, meta.flags.clone().unwrap_or_default());
            }
        }
        Ok(tonic::Response::new(mail_proto::GetFlagsResponse { flags }))
    }

    async fn move_message(
        &self,
        request: tonic::Request<mail_proto::MoveMessageRequest>,
    ) -> Result<tonic::Response<mail_proto::MoveMessageResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("move_message") {
            return Err(tonic::Status::unavailable("mock move_message failure"));
        }
        if !g
            .mailboxes
            .get(&req.account_id)
            .map(|m| m.contains_key(&req.dest_mailbox.to_lowercase()))
            .unwrap_or(false)
        {
            return Err(tonic::Status::not_found("no such destination mailbox"));
        }
        let mut mapping = HashMap::new();
        let source_key = (req.account_id.clone(), req.source_mailbox.to_lowercase());
        let moved: Vec<mail_proto::MessageMeta> = {
            let bucket = g
                .messages
                .entry(req.account_id.clone())
                .or_default()
                .entry(req.source_mailbox.to_lowercase())
                .or_default();
            let (moved, kept): (Vec<_>, Vec<_>) = bucket
                .iter()
                .cloned()
                .partition(|m| req.uids.contains(&m.uid));
            *bucket = kept;
            moved
        };
        for mut meta in moved {
            let dest_row = g
                .mailboxes
                .entry(req.account_id.clone())
                .or_default()
                .entry(req.dest_mailbox.to_lowercase())
                .or_insert_with(|| mail_proto::Mailbox {
                    name: req.dest_mailbox.clone(),
                    uidvalidity: 1,
                    uidnext: 1,
                    ..Default::default()
                });
            let new_uid = dest_row.uidnext;
            dest_row.uidnext += 1;
            dest_row.exists += 1;
            mapping.insert(meta.uid, new_uid);
            let old_uid = meta.uid;
            meta.uid = new_uid;
            meta.mailbox = req.dest_mailbox.clone();
            let body = g
                .bodies
                .remove(&(source_key.0.clone(), source_key.1.clone(), old_uid));
            if let Some(body) = body {
                g.bodies.insert(
                    (
                        req.account_id.clone(),
                        req.dest_mailbox.to_lowercase(),
                        new_uid,
                    ),
                    body,
                );
            }
            g.messages
                .entry(req.account_id.clone())
                .or_default()
                .entry(req.dest_mailbox.to_lowercase())
                .or_default()
                .push(meta);
        }
        // Keep the source row's EXISTS in sync.
        let source_len = g
            .messages
            .get(&req.account_id)
            .and_then(|m| m.get(&req.source_mailbox.to_lowercase()))
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        if let Some(row) = g
            .mailboxes
            .get_mut(&req.account_id)
            .and_then(|m| m.get_mut(&req.source_mailbox.to_lowercase()))
        {
            row.exists = source_len;
        }
        g.calls.push((
            "move_message".to_string(),
            format!("{:?}|{}", req.uids, req.dest_mailbox),
        ));
        Ok(tonic::Response::new(mail_proto::MoveMessageResponse {
            uid_mapping: mapping,
        }))
    }

    async fn copy_message(
        &self,
        request: tonic::Request<mail_proto::CopyMessageRequest>,
    ) -> Result<tonic::Response<mail_proto::CopyMessageResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("copy_message") {
            return Err(tonic::Status::unavailable("mock copy_message failure"));
        }
        if !g
            .mailboxes
            .get(&req.account_id)
            .map(|m| m.contains_key(&req.dest_mailbox.to_lowercase()))
            .unwrap_or(false)
        {
            return Err(tonic::Status::not_found("no such destination mailbox"));
        }
        let mut mapping = HashMap::new();
        let copies: Vec<mail_proto::MessageMeta> = g
            .messages
            .get(&req.account_id)
            .and_then(|m| m.get(&req.source_mailbox.to_lowercase()))
            .map(|v| {
                v.iter()
                    .filter(|m| req.uids.contains(&m.uid))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for mut meta in copies {
            let dest_row = g
                .mailboxes
                .entry(req.account_id.clone())
                .or_default()
                .entry(req.dest_mailbox.to_lowercase())
                .or_insert_with(|| mail_proto::Mailbox {
                    name: req.dest_mailbox.clone(),
                    uidvalidity: 1,
                    uidnext: 1,
                    ..Default::default()
                });
            let new_uid = dest_row.uidnext;
            dest_row.uidnext += 1;
            dest_row.exists += 1;
            mapping.insert(meta.uid, new_uid);
            meta.uid = new_uid;
            meta.mailbox = req.dest_mailbox.clone();
            g.messages
                .entry(req.account_id.clone())
                .or_default()
                .entry(req.dest_mailbox.to_lowercase())
                .or_default()
                .push(meta);
        }
        g.calls.push((
            "copy_message".to_string(),
            format!("{:?}|{}", req.uids, req.dest_mailbox),
        ));
        Ok(tonic::Response::new(mail_proto::CopyMessageResponse {
            uid_mapping: mapping,
        }))
    }

    async fn create_mailbox(
        &self,
        request: tonic::Request<mail_proto::CreateMailboxRequest>,
    ) -> Result<tonic::Response<mail_proto::CreateMailboxResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("create_mailbox") {
            return Err(tonic::Status::unavailable("mock create_mailbox failure"));
        }
        g.mailboxes
            .entry(req.account_id.clone())
            .or_default()
            .insert(
                req.name.to_lowercase(),
                mail_proto::Mailbox {
                    name: req.name.clone(),
                    delimiter: "/".to_string(),
                    uidvalidity: 7,
                    uidnext: 1,
                    ..Default::default()
                },
            );
        g.calls
            .push(("create_mailbox".to_string(), req.name.clone()));
        Ok(tonic::Response::new(mail_proto::CreateMailboxResponse {
            mailbox: Some(mail_proto::Mailbox {
                name: req.name,
                delimiter: "/".to_string(),
                ..Default::default()
            }),
        }))
    }

    async fn delete_mailbox(
        &self,
        request: tonic::Request<mail_proto::DeleteMailboxRequest>,
    ) -> Result<tonic::Response<mail_proto::DeleteMailboxResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("delete_mailbox") {
            return Err(tonic::Status::unavailable("mock delete_mailbox failure"));
        }
        let existed = g
            .mailboxes
            .entry(req.account_id.clone())
            .or_default()
            .remove(&req.name.to_lowercase())
            .is_some();
        g.messages
            .entry(req.account_id.clone())
            .or_default()
            .remove(&req.name.to_lowercase());
        g.calls
            .push(("delete_mailbox".to_string(), req.name.clone()));
        Ok(tonic::Response::new(mail_proto::DeleteMailboxResponse {
            success: existed,
        }))
    }

    async fn list_mailboxes(
        &self,
        request: tonic::Request<mail_proto::ListMailboxesRequest>,
    ) -> Result<tonic::Response<mail_proto::ListMailboxesResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("list_mailboxes") {
            return Err(tonic::Status::unavailable("mock list_mailboxes failure"));
        }
        let mailboxes = g
            .mailboxes
            .get(&req.account_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        Ok(tonic::Response::new(mail_proto::ListMailboxesResponse {
            mailboxes,
        }))
    }

    async fn get_mailbox_status(
        &self,
        request: tonic::Request<mail_proto::GetMailboxStatusRequest>,
    ) -> Result<tonic::Response<mail_proto::GetMailboxStatusResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("get_mailbox_status") {
            return Err(tonic::Status::unavailable("mock status failure"));
        }
        let row = g
            .mailboxes
            .get(&req.account_id)
            .and_then(|m| m.get(&req.mailbox.to_lowercase()))
            .cloned()
            .ok_or_else(|| tonic::Status::not_found("no such mailbox"))?;
        let highest_modseq = {
            let count = g
                .messages
                .get(&req.account_id)
                .and_then(|m| m.get(&req.mailbox.to_lowercase()))
                .map(|v| v.len())
                .unwrap_or(0);
            row.uidnext
                .saturating_mul(1_000_000)
                .saturating_add(count as u64)
        };
        Ok(tonic::Response::new(mail_proto::GetMailboxStatusResponse {
            mailbox: Some(row),
            highest_modseq,
        }))
    }

    async fn expunge(
        &self,
        request: tonic::Request<mail_proto::ExpungeRequest>,
    ) -> Result<tonic::Response<mail_proto::ExpungeResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("expunge") {
            return Err(tonic::Status::unavailable("mock expunge failure"));
        }
        let restricted = !req.uids.is_empty();
        let bucket = g
            .messages
            .entry(req.account_id.clone())
            .or_default()
            .entry(req.mailbox.to_lowercase())
            .or_default();
        let mut expunged = Vec::new();
        bucket.retain(|meta| {
            let deleted = meta.flags.clone().unwrap_or_default().deleted;
            let targeted = !restricted || req.uids.contains(&meta.uid);
            if deleted && targeted {
                expunged.push(meta.uid);
                false
            } else {
                true
            }
        });
        let remaining = bucket.len() as u32;
        if let Some(row) = g
            .mailboxes
            .get_mut(&req.account_id)
            .and_then(|m| m.get_mut(&req.mailbox.to_lowercase()))
        {
            row.exists = remaining;
        }
        g.calls.push((
            "expunge".to_string(),
            format!("{:?}|{}", req.uids, req.mailbox),
        ));
        Ok(tonic::Response::new(mail_proto::ExpungeResponse {
            expunged_uids: expunged,
        }))
    }

    async fn create_account(
        &self,
        request: tonic::Request<mail_proto::CreateAccountRequest>,
    ) -> Result<tonic::Response<mail_proto::CreateAccountResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        let id = format!("acct-{}", req.email);
        g.accounts
            .insert(req.email.to_lowercase(), (id.clone(), req.password.clone()));
        Ok(tonic::Response::new(mail_proto::CreateAccountResponse {
            account_id: id,
        }))
    }

    async fn get_account(
        &self,
        request: tonic::Request<mail_proto::GetAccountRequest>,
    ) -> Result<tonic::Response<mail_proto::GetAccountResponse>, tonic::Status> {
        let req = request.into_inner();
        let g = self.lock();
        if g.fail.contains("get_account") {
            return Err(tonic::Status::unavailable("mock get_account failure"));
        }
        let key = if req.account_id.is_empty() {
            req.email.to_lowercase()
        } else {
            req.account_id.clone()
        };
        let found = g
            .accounts
            .iter()
            .find(|(email, (id, _))| email.as_str() == key || id == &key)
            .map(|(email, (id, _))| (email.clone(), id.clone()));
        match found {
            Some((email, id)) => Ok(tonic::Response::new(mail_proto::GetAccountResponse {
                account_id: id,
                email,
                display_name: "Test".to_string(),
                created_at: 0,
                active: true,
            })),
            None => Err(tonic::Status::not_found("no such account")),
        }
    }

    async fn authenticate_account(
        &self,
        request: tonic::Request<mail_proto::AuthenticateRequest>,
    ) -> Result<tonic::Response<mail_proto::AuthenticateResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut g = self.lock();
        if g.fail.contains("authenticate_account") {
            return Err(tonic::Status::unavailable("mock auth failure"));
        }
        g.calls
            .push(("authenticate_account".to_string(), req.email.clone()));
        match g.accounts.get(&req.email.to_lowercase()) {
            Some((id, password)) if password == &req.password => {
                Ok(tonic::Response::new(mail_proto::AuthenticateResponse {
                    success: true,
                    account_id: id.clone(),
                    error: String::new(),
                }))
            }
            _ => Ok(tonic::Response::new(mail_proto::AuthenticateResponse {
                success: false,
                account_id: String::new(),
                error: "Invalid credentials".to_string(),
            })),
        }
    }

    async fn get_quota(
        &self,
        request: tonic::Request<mail_proto::GetQuotaRequest>,
    ) -> Result<tonic::Response<mail_proto::GetQuotaResponse>, tonic::Status> {
        let _ = request.into_inner();
        Ok(tonic::Response::new(mail_proto::GetQuotaResponse {
            quota: Some(mail_proto::Quota {
                used_bytes: 10,
                max_bytes: 1000,
                used_messages: 1,
                max_messages: 100,
            }),
        }))
    }

    async fn subscribe_mailbox(
        &self,
        request: tonic::Request<mail_proto::SubscribeMailboxRequest>,
    ) -> Result<tonic::Response<Self::SubscribeMailboxStream>, tonic::Status> {
        let req = request.into_inner();
        self.lock().calls.push((
            "subscribe_mailbox".to_string(),
            format!("{}|{}", req.account_id, req.mailbox),
        ));
        let (tx, rx) = mpsc::unbounded_channel();
        self.lock().events.insert(
            format!("{}|{}", req.account_id, req.mailbox.to_lowercase()),
            tx,
        );
        Ok(tonic::Response::new(MockEventStream(rx)))
    }
}

// ── in-memory gRPC transport ────────────────────────────────────────────────

/// A `tower_service::Service<Uri>` that mints a fresh in-memory duplex pair
/// per connection and feeds the server halves to the tonic server.
struct DuplexConnector {
    tx: mpsc::UnboundedSender<Result<DuplexStream, std::io::Error>>,
}

impl tonic::codegen::Service<tonic::codegen::http::Uri> for DuplexConnector {
    type Response = hyper_util::rt::TokioIo<DuplexStream>;
    type Error = std::io::Error;
    type Future = Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<hyper_util::rt::TokioIo<DuplexStream>, std::io::Error>,
                > + Send,
        >,
    >;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: tonic::codegen::http::Uri) -> Self::Future {
        let (client, server) = tokio::io::duplex(1 << 20);
        let tx = self.tx.clone();
        let _ = tx.send(Ok(server));
        Box::pin(async move { Ok(hyper_util::rt::TokioIo::new(client)) })
    }
}

pub(crate) fn mock_connected_client(mock: MockMailstore) -> MailstoreClient {
    let (tx, rx) = mpsc::unbounded_channel::<Result<DuplexStream, std::io::Error>>();
    let mut rx = rx;
    let incoming = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(MailstoreServiceServer::new(mock))
            .serve_with_incoming(incoming)
            .await;
    });
    let channel = tonic::transport::Endpoint::from_static("http://in-memory.mailstore:50051")
        .connect_with_connector_lazy(DuplexConnector { tx });
    build_mailstore_client(
        channel,
        mail_proto::InternalServiceAuthInterceptor::new(None)
            .expect("tokenless interceptor is constructible"),
    )
}

// ── session harness ─────────────────────────────────────────────────────────

struct Harness {
    mock: MockMailstore,
    session: Arc<Mutex<ImapSession>>,
    io: BufReader<DuplexStream>,
    server: tokio::task::JoinHandle<Result<()>>,
    next_tag: u32,
}

impl Harness {
    fn new() -> Self {
        Self::with_policy("127.0.0.1", false, true)
    }

    fn with_policy(peer_ip: &str, allow_insecure_auth: bool, send_greeting: bool) -> Self {
        Self::with_session(peer_ip, true, allow_insecure_auth, send_greeting)
    }

    /// `tls_active`: session starts on a TLS leg; `allow_insecure_auth`
    /// mirrors the CLI flag; `send_greeting` drives the real `serve` entry.
    fn with_session(
        peer_ip: &str,
        tls_active: bool,
        allow_insecure_auth: bool,
        send_greeting: bool,
    ) -> Self {
        let mock = MockMailstore::new();
        let mut raw_session = ImapSession::new(mock_connected_client(mock.clone()));
        raw_session.tls_active = tls_active;
        raw_session.allow_insecure_auth = allow_insecure_auth;
        raw_session.peer_ip = peer_ip.to_string();
        let session = Arc::new(Mutex::new(raw_session));
        let (client, server) = tokio::io::duplex(1 << 20);
        let (sr, sw) = tokio::io::split(server);
        let task_session = session.clone();
        let server = tokio::spawn(async move { serve(task_session, sr, sw, send_greeting).await });
        Self {
            mock,
            session,
            io: BufReader::new(client),
            server,
            next_tag: 0,
        }
    }

    /// Consume the server greeting (only when `send_greeting` was used).
    async fn read_greeting(&mut self) {
        let mut greeting = Vec::new();
        self.io
            .read_until(b'\n', &mut greeting)
            .await
            .expect("greeting read");
        assert!(
            greeting.starts_with(b"* OK"),
            "greeting: {:?}",
            String::from_utf8_lossy(&greeting)
        );
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.io
            .get_mut()
            .write_all(bytes)
            .await
            .expect("test write to server");
        self.io.get_mut().flush().await.expect("test flush");
    }

    async fn send_line(&mut self, line: &str) {
        self.send_raw(format!("{line}\r\n").as_bytes()).await;
    }

    /// Read raw lines until one begins with `tag ` (or is exactly `tag`).
    async fn read_until_tagged(&mut self, tag: &str) -> String {
        let mut out = Vec::new();
        let needle = format!("{tag} ");
        for _ in 0..200 {
            let mut line = Vec::new();
            let n = tokio::time::timeout(
                Duration::from_secs(10),
                self.io.read_until(b'\n', &mut line),
            )
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {tag}, got so far: {:?}", out))
            .expect("server read");
            if n == 0 {
                break;
            }
            let is_tagged = line.starts_with(needle.as_bytes())
                || line.starts_with(format!("{tag}\r\n").as_bytes())
                || line.starts_with(format!("{tag}\n").as_bytes());
            out.extend_from_slice(&line);
            if is_tagged {
                break;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn fresh_tag(&mut self) -> String {
        self.next_tag += 1;
        format!("A{:03}", self.next_tag)
    }

    /// Send `command` under a fresh tag and return the complete transcript.
    async fn cmd(&mut self, command: &str) -> String {
        let tag = self.fresh_tag();
        self.send_line(&format!("{tag} {command}")).await;
        self.read_until_tagged(&tag).await
    }

    /// Same as [`Self::cmd`] but returns `(tag, transcript)`.
    async fn cmd_tagged(&mut self, command: &str) -> (String, String) {
        let tag = self.fresh_tag();
        self.send_line(&format!("{tag} {command}")).await;
        let out = self.read_until_tagged(&tag).await;
        (tag, out)
    }

    /// Drive a command whose argument carries a synchronizing literal: send
    /// the announcement, wait for the `+` continuation, then send the bytes.
    async fn cmd_with_literal(&mut self, prefix: &str, literal: &[u8], suffix: &str) -> String {
        let tag = self.fresh_tag();
        self.send_line(&format!("{tag} {prefix}{{{}}}{suffix}", literal.len()))
            .await;
        let mut cont = Vec::new();
        let n = tokio::time::timeout(
            Duration::from_secs(10),
            self.io.read_until(b'\n', &mut cont),
        )
        .await
        .expect("continuation timeout")
        .expect("read continuation");
        assert!(n > 0, "server closed before continuation");
        assert!(
            cont.starts_with(b"+"),
            "expected continuation request, got {:?}",
            String::from_utf8_lossy(&cont)
        );
        self.send_raw(literal).await;
        self.send_line(suffix).await;
        self.read_until_tagged(&tag).await
    }

    /// Authenticate the session directly (bypassing LOGIN I/O where the test
    /// only needs the authenticated state) and select a mailbox through the
    /// real SELECT command.
    async fn login(&mut self, email: &str, password: &str) {
        self.mock.add_account(email, "acct-1", password);
        let tag = self.fresh_tag();
        self.send_line(&format!("{tag} LOGIN {email} {password}"))
            .await;
        let out = self.read_until_tagged(&tag).await;
        assert!(
            out.contains("OK"),
            "LOGIN should succeed for the mock account, got {out:?}"
        );
    }

    async fn select(&mut self, mailbox: &str) {
        let out = self.cmd(&format!("SELECT {mailbox}")).await;
        assert!(
            out.contains("OK"),
            "SELECT {mailbox} should succeed, got {out:?}"
        );
    }

    /// Flush pending output: done by issuing NOOP and reading its response.
    async fn noop(&mut self) -> String {
        self.cmd("NOOP").await
    }

    async fn shutdown(mut self) {
        let _ = self.send_line("A999 LOGOUT").await;
        let _ = self.read_until_tagged("A999").await;
        let _ = tokio::time::timeout(Duration::from_secs(5), self.server).await;
    }
}

// ── greeting / capability / auth policy ─────────────────────────────────────

#[tokio::test]
async fn greeting_and_capability_are_rfc3501_shaped() {
    let mut h = Harness::new();
    let mut greeting = Vec::new();
    h.io.read_until(b'\n', &mut greeting).await.unwrap();
    let greeting = String::from_utf8_lossy(&greeting);
    assert!(
        greeting.starts_with("* OK"),
        "greeting must be untagged OK, got {greeting:?}"
    );
    assert!(greeting.contains("ApexMail"), "greeting: {greeting:?}");

    let out = h.cmd("CAPABILITY").await;
    assert!(out.contains("* CAPABILITY IMAP4rev1"), "{out:?}");
    assert!(
        out.contains("AUTH=PLAIN"),
        "TLS session advertises AUTH=PLAIN: {out:?}"
    );
    // RFC 3501 §6.2.1: STARTTLS must NOT be advertised on a TLS leg.
    assert!(
        !out.contains("STARTTLS"),
        "STARTTLS advertised on a TLS connection: {out:?}"
    );
    assert!(
        out.trim_end()
            .trim_end()
            .ends_with("OK CAPABILITY completed"),
        "{out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn plaintext_session_refuses_login_and_starttls_policy() {
    // tls_active=false + allow_insecure_auth=false: RFC 3501 [PRIVACYREQUIRED].
    let mut h = Harness::with_session("10.0.0.9", false, false, true);
    // Prepare the account so a refusal can only come from the policy gate.
    h.mock.add_account("user@example.test", "acct-1", "pw");
    // Greeting still works.
    let mut greeting = Vec::new();
    h.io.read_until(b'\n', &mut greeting).await.unwrap();

    let out = h.cmd("LOGIN user@example.test pw").await;
    assert!(
        out.contains("NO [PRIVACYREQUIRED]"),
        "plaintext LOGIN must be refused with PRIVACYREQUIRED: {out:?}"
    );
    assert!(
        !out.contains("OK LOGIN"),
        "plaintext LOGIN must not authenticate: {out:?}"
    );

    // The auth state must not have leaked.
    let out = h.cmd("NAMESPACE").await;
    assert!(
        out.contains("NO Not authenticated"),
        "session must stay unauthenticated: {out:?}"
    );

    // The mock must never have seen an authenticate attempt.
    assert!(
        h.mock.recorded("authenticate_account").is_empty(),
        "no credential RPC may run for a refused plaintext LOGIN"
    );

    // STARTTLS is not available in this harness leg (already past it) — the
    // dispatcher answers BAD because it is only valid at the connection level.
    let out = h.cmd("STARTTLS").await;
    assert!(out.contains("BAD"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn login_wrong_password_is_no_and_second_login_is_bad() {
    let mut h = Harness::new();
    let _ = h.cmd("CAPABILITY").await;
    let out = h.cmd("LOGIN user@example.test wrongpw").await;
    assert!(
        out.contains("NO LOGIN failed: Invalid credentials"),
        "{out:?}"
    );
    assert!(
        !h.mock.recorded("authenticate_account").is_empty(),
        "the credential RPC must have been attempted"
    );
    // Still unauthenticated: a SELECT must be refused.
    let out = h.cmd("SELECT INBOX").await;
    assert!(out.contains("NO Not authenticated"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn login_after_login_is_bad_and_does_not_reauthenticate() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("LOGIN other@example.test pw").await;
    assert!(
        out.contains("BAD Already authenticated"),
        "RFC 3501: LOGIN in authenticated state is BAD: {out:?}"
    );
    let state = h.session.lock().await.state;
    assert_eq!(state, SessionState::Authenticated);
    h.shutdown().await;
}

#[tokio::test]
async fn login_requires_two_arguments() {
    let mut h = Harness::new();
    let out = h.cmd("LOGIN onlyuser").await;
    assert!(out.contains("BAD"), "one-arg LOGIN: {out:?}");
    let out = h.cmd("LOGIN a b c").await;
    assert!(out.contains("BAD"), "three-arg LOGIN: {out:?}");
    let out = h.cmd("LOGIN").await;
    assert!(out.contains("BAD"), "no-arg LOGIN: {out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn login_with_literal_username_and_password() {
    let mut h = Harness::new();
    h.mock.add_account("lit@example.test", "acct-1", "s3cret");
    let mut greeting = Vec::new();
    h.io.read_until(b'\n', &mut greeting).await.unwrap();
    // Username as a synchronizing literal, password quoted.
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} LOGIN {{16}}")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert!(cont.starts_with(b"+"), "continuation: {cont:?}");
    h.send_raw(b"lit@example.test").await;
    h.send_line(" \"s3cret\"").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("OK LOGIN succeeded"), "{out:?}");
    assert_eq!(h.session.lock().await.account_id, "acct-1");
    h.shutdown().await;
}

#[tokio::test]
async fn unknown_command_and_unknown_uid_subcommand_are_bad() {
    let mut h = Harness::new();
    let out = h.cmd("FROBNICATE now").await;
    assert!(out.contains("BAD Unknown command"), "{out:?}");
    h.login("user@example.test", "pw").await;
    let out = h.cmd("UID FROB 1:*").await;
    assert!(out.contains("BAD Unknown UID sub-command: FROB"), "{out:?}");
    h.shutdown().await;
}

// ── SELECT / EXAMINE ────────────────────────────────────────────────────────

#[tokio::test]
async fn select_nonexistent_mailbox_is_no_nonexistent() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("SELECT Missing").await;
    assert!(
        out.contains("NO [NONEXISTENT] Mailbox not found"),
        "{out:?}"
    );
    assert_eq!(h.session.lock().await.state, SessionState::Authenticated);
    h.shutdown().await;
}

#[tokio::test]
async fn select_success_reports_view_and_uidvalidity() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 424242);
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "hello",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1000,
    );
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "seen one",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: true,
            deleted: false,
            ..Default::default()
        },
        2000,
    );
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "gone",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: true,
            ..Default::default()
        },
        3000,
    );

    let out = h.cmd("SELECT INBOX").await;
    assert!(out.contains("* 3 EXISTS"), "{out:?}");
    assert!(out.contains("* 2 RECENT"), "{out:?}");
    assert!(
        out.contains("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)"),
        "{out:?}"
    );
    assert!(
        out.contains("[PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft \\*)]"),
        "{out:?}"
    );
    assert!(out.contains("OK [UIDVALIDITY 424242]"), "{out:?}");
    assert!(out.contains("OK [UIDNEXT 4]"), "{out:?}");
    assert!(
        out.contains("* OK [UNSEEN 1] First unseen message"),
        "{out:?}"
    );
    assert!(
        out.contains("OK [READ-WRITE] SELECT completed, 3 messages"),
        "{out:?}"
    );

    let s = h.session.lock().await;
    assert_eq!(s.uid_map, vec![1, 2, 3]);
    assert_eq!(s.uid_validity, 424242);
    assert_eq!(s.recent_uids.len(), 2);
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn examine_is_read_only_and_store_expunge_are_refused() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "x",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: true,
            ..Default::default()
        },
        1000,
    );

    let out = h.cmd("EXAMINE INBOX").await;
    assert!(out.contains("OK [READ-ONLY] EXAMINE completed"), "{out:?}");
    assert!(h.session.lock().await.read_only);
    // A body FETCH on an EXAMINEd mailbox must not set \Seen.
    let out = h.cmd("FETCH 1 BODY[]").await;
    assert!(out.contains("OK FETCH completed"), "{out:?}");
    assert!(
        h.mock.recorded("set_flags").is_empty(),
        "read-only FETCH must not write flags: {:?}",
        h.mock.recorded("set_flags")
    );
    let out = h.cmd("STORE 1 +FLAGS (\\Seen)").await;
    assert!(
        out.contains("NO [READ-ONLY] STORE not permitted"),
        "{out:?}"
    );
    let out = h.cmd("EXPUNGE").await;
    assert!(
        out.contains("NO [READ-ONLY] EXPUNGE not permitted"),
        "{out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn select_of_unverifiable_mailbox_deselects_previous_view() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "x",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1000,
    );
    h.select("INBOX").await;
    assert_eq!(h.session.lock().await.state, SessionState::Selected);

    // RFC 9051 §6.3.4: a failed SELECT leaves NO mailbox selected.
    let out = h.cmd("SELECT Missing").await;
    assert!(out.contains("NO [NONEXISTENT]"), "{out:?}");
    let s = h.session.lock().await;
    assert_eq!(s.state, SessionState::Authenticated);
    assert!(s.mailbox.is_empty());
    assert!(s.uid_map.is_empty());
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn select_on_list_failure_reports_no_and_deselects() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    h.mock.add_mailbox("acct-1", "Other", 2);
    h.mock.fail("list_messages");
    let out = h.cmd("SELECT Other").await;
    assert!(out.contains("NO Failed to list messages"), "{out:?}");
    let s = h.session.lock().await;
    assert_eq!(s.state, SessionState::Authenticated);
    assert!(s.mailbox.is_empty());
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn select_transport_failure_is_no_not_silent_ok() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.mock.fail("get_mailbox_status");
    let out = h.cmd("SELECT INBOX").await;
    assert!(out.contains("NO Failed to open mailbox"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn select_addresses_only_the_sessions_own_account() {
    // Cross-tenant isolation: account acct-2 has a mailbox named INBOX with
    // messages; acct-1 has none. The session must see acct-1's view only.
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-2", "INBOX", 99);
    h.mock.add_message(
        "acct-2",
        "INBOX",
        "secret",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1,
    );
    h.mock.add_mailbox("acct-1", "INBOX", 5);

    let out = h.cmd("SELECT INBOX").await;
    assert!(
        out.contains("* 0 EXISTS"),
        "must not see acct-2's mail: {out:?}"
    );
    assert!(out.contains("OK [UIDVALIDITY 5]"), "{out:?}");
    assert!(!out.contains("99"), "acct-2 uidvalidity leaked: {out:?}");
    h.shutdown().await;
}

// ── LIST / LSUB / SUBSCRIBE / STATUS ────────────────────────────────────────

#[tokio::test]
async fn list_filters_patterns_and_adds_subscribed_attribute() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.mock.add_mailbox("acct-1", "Work", 2);
    h.mock.add_mailbox("acct-1", "Work/Projects", 3);
    h.mock.add_mailbox("acct-2", "Foreign", 4);

    // SUBSCRIBE then LIST: \Subscribed attribute must appear.
    let out = h.cmd("SUBSCRIBE Work").await;
    assert!(out.contains("OK SUBSCRIBE completed, Work"), "{out:?}");

    let out = h.cmd("LIST \"\" \"Work*\"").await;
    assert!(
        out.contains("* LIST (\\Subscribed) \"/\" \"Work\""),
        "{out:?}"
    );
    assert!(out.contains("\"Work/Projects\""), "{out:?}");
    assert!(
        !out.contains("INBOX"),
        "pattern Work* must not list INBOX: {out:?}"
    );
    assert!(!out.contains("Foreign"), "cross-tenant leak: {out:?}");

    let out = h.cmd("LIST \"\" \"\"").await;
    assert!(out.contains("OK LIST completed"), "{out:?}");

    let out = h.cmd("UNSUBSCRIBE Work").await;
    assert!(out.contains("OK UNSUBSCRIBE completed, Work"), "{out:?}");
    let out = h.cmd("LIST \"\" Work").await;
    assert!(
        !out.contains("\\Subscribed"),
        "unsubscribed name keeps no attribute: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn lsub_lists_subscribed_names_even_when_mailbox_vanished() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "Docs", 1);
    h.cmd("SUBSCRIBE Docs").await;
    h.cmd("SUBSCRIBE Ghost").await;
    h.mock
        .lock()
        .mailboxes
        .get_mut("acct-1")
        .unwrap()
        .remove("docs");

    let out = h.cmd("LSUB \"\" \"*\"").await;
    assert!(
        out.contains("* LSUB () \"/\" \"Docs\""),
        "existing name attrs: {out:?}"
    );
    assert!(
        out.contains("* LSUB () \"/\" \"Ghost\""),
        "a subscribed-but-vanished name is still listed: {out:?}"
    );
    let out = h.cmd("LSUB \"\" \"Doc*\"").await;
    assert!(out.contains("Docs"), "{out:?}");
    assert!(!out.contains("Ghost"), "pattern filters LSUB too: {out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn list_failure_is_no() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.fail("list_mailboxes");
    let out = h.cmd("LIST \"\" \"*\"").await;
    assert!(out.contains("NO LIST failed"), "{out:?}");
    let out = h.cmd("LSUB \"\" \"*\"").await;
    assert!(out.contains("NO LSUB failed"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn status_reports_requested_items_and_uidvalidity() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 777);
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "a",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1,
    );
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "b",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: true,
            deleted: false,
            ..Default::default()
        },
        1,
    );
    h.mock
        .lock()
        .mailboxes
        .get_mut("acct-1")
        .unwrap()
        .get_mut("inbox")
        .unwrap()
        .unseen = 1;

    let out = h
        .cmd("STATUS INBOX (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)")
        .await;
    assert!(
        out.contains("* STATUS \"INBOX\" (MESSAGES 2 RECENT 0 UIDNEXT 3 UIDVALIDITY 777 UNSEEN 1)"),
        "{out:?}"
    );
    assert!(out.contains("OK STATUS completed"), "{out:?}");

    let out = h.cmd("STATUS INBOX (MESSAGES)").await;
    assert!(
        !out.contains("UIDNEXT"),
        "unrequested items must not be reported: {out:?}"
    );

    let out = h.cmd("STATUS Missing (MESSAGES)").await;
    assert!(
        out.contains("NO [NONEXISTENT] Mailbox not found"),
        "{out:?}"
    );

    let out = h.cmd("STATUS").await;
    assert!(out.contains("BAD Mailbox name required"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn commands_requiring_auth_are_refused_before_authentication() {
    let mut h = Harness::new();
    for cmd in [
        "SELECT INBOX",
        "EXAMINE INBOX",
        "CREATE New",
        "DELETE New",
        "RENAME A B",
        "LIST \"\" \"*\"",
        "LSUB \"\" \"*\"",
        "SUBSCRIBE X",
        "UNSUBSCRIBE X",
        "STATUS INBOX (MESSAGES)",
        "APPEND INBOX",
        "NAMESPACE",
    ] {
        let out = h.cmd(cmd).await;
        assert!(
            out.contains("NO Not authenticated"),
            "{cmd} must be refused pre-auth, got {out:?}"
        );
    }
    h.shutdown().await;
}

// ── FETCH ───────────────────────────────────────────────────────────────────

/// Common selection: one unseen + one seen message with bodies.
async fn select_two_messages(h: &mut Harness) -> (u64, u64) {
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 11);
    let u1 = h.mock.add_message(
        "acct-1",
        "INBOX",
        "alpha",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1000,
    );
    let u2 = h.mock.add_message(
        "acct-1",
        "INBOX",
        "beta",
        "c@d.test",
        mail_proto::MessageFlags {
            seen: true,
            deleted: false,
            ..Default::default()
        },
        2000,
    );
    h.mock.set_body(
        "acct-1",
        "INBOX",
        u1,
        b"From: a@b.test\r\nSubject: alpha\r\nTo: rcpt@example.test\r\n\r\nbody one\r\n",
    );
    h.mock
        .set_body("acct-1", "INBOX", u2, b"Subject: beta\r\n\r\nbody two\r\n");
    h.select("INBOX").await;
    (u1, u2)
}

#[tokio::test]
async fn fetch_all_macro_emits_the_expected_attributes() {
    let mut h = Harness::new();
    let (_, _) = select_two_messages(&mut h).await;
    let out = h.cmd("FETCH 1 ALL").await;
    assert!(
        out.contains("* 1 FETCH (FLAGS (\\Recent) INTERNALDATE"),
        "{out:?}"
    );
    assert!(
        out.contains("RFC822.SIZE 100 ENVELOPE "),
        "RFC 3501 ALL includes RFC822.SIZE: {out:?}"
    );
    assert!(out.contains("OK FETCH completed"), "{out:?}");
    // ALL is a macro: no BODY/BODYSTRUCTURE literal.
    assert!(!out.contains("BODY"), "ALL must not include BODY: {out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_seen_side_effect_and_peek() {
    let mut h = Harness::new();
    let (u1, _) = select_two_messages(&mut h).await;
    // Non-peek BODY[] on an unseen message sets \Seen (persisted through the
    // store; explicitly requesting FLAGS shows the post-operation state).
    let out = h.cmd("FETCH 1 (BODY[] FLAGS)").await;
    assert!(out.contains("FLAGS (\\Seen \\Recent)"), "{out:?}");
    assert!(out.contains("BODY[] {"), "{out:?}");
    let calls = h.mock.recorded("set_flags");
    assert_eq!(calls.len(), 1, "exactly one flag write: {calls:?}");
    assert!(calls[0].contains("Add"), "{calls:?}");
    assert!(calls[0].contains(&u1.to_string()), "{calls:?}");

    // BODY.PEEK[HEADER] must NOT set \Seen.
    let out = h.cmd("FETCH 2 BODY.PEEK[HEADER]").await;
    assert!(out.contains("BODY[HEADER] {"), "{out:?}");
    assert_eq!(
        h.mock.recorded("set_flags").len(),
        1,
        "peek must not write flags"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_uid_mode_prepends_uid_exactly_once() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let out = h.cmd("UID FETCH 2 (UID FLAGS)").await;
    assert_eq!(
        out.matches("UID 2").count(),
        1,
        "UID must be emitted once: {out:?}"
    );
    assert!(out.contains("* 2 FETCH (UID 2 FLAGS"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_partial_and_header_fields() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let out = h.cmd("FETCH 1 BODY.PEEK[HEADER]<0.9>").await;
    assert!(out.contains("BODY[HEADER]<0> {9}"), "{out:?}");
    let out = h.cmd("FETCH 1 BODY.PEEK[HEADER.FIELDS (SUBJECT)]").await;
    assert!(out.contains("BODY[HEADER.FIELDS (SUBJECT)] {"), "{out:?}");
    assert!(out.contains("Subject: alpha"), "{out:?}");
    // The field filter must drop non-requested fields.
    assert!(
        !out.contains("From: a@b.test"),
        "header filter leaked: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_body_section_errors_are_bad() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    for cmd in [
        "FETCH 1 BODY[99.],",
        "FETCH 1 BODY[HEADER.FIELDS]",
        "FETCH 1 BODY[1.]",
        "FETCH 1 FROBNICATE",
        "FETCH 1 BODY.PEEK[HEADER]<0.0>",
        "FETCH 1 BODY.PEEK[HEADER]<abc.5>",
        "FETCH 1",
    ] {
        let out = h.cmd(cmd).await;
        assert!(out.contains("BAD"), "{cmd} must be BAD, got {out:?}");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_sequence_set_edge_cases() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;

    // `*` resolves to the last message.
    let out = h.cmd("FETCH * UID").await;
    assert!(out.contains("* 2 FETCH (UID 2)"), "{out:?}");

    // A reversed range is normalized (RFC 3501 §9: 2:1 == 1:2).
    let out = h.cmd("FETCH 2:1 UID").await;
    assert!(out.contains("UID 1") && out.contains("UID 2"), "{out:?}");

    // Out-of-range numbers resolve to nothing — OK, no data.
    let (tag, out) = h.cmd_tagged("FETCH 99 UID").await;
    assert_eq!(out, format!("{tag} OK FETCH completed\r\n"));

    // `0` is not a valid sequence number and is skipped.
    let out = h.cmd("FETCH 0 UID").await;
    assert!(out.contains("OK FETCH completed"), "{out:?}");

    // Garbage is a BAD, not a silent empty result.
    let out = h.cmd("FETCH abc UID").await;
    assert!(out.contains("BAD invalid sequence"), "{out:?}");
    let out = h.cmd("FETCH 1: UID").await;
    assert!(out.contains("BAD"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_missing_mailbox_is_bad_before_auth_state_check() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("FETCH 1 UID").await;
    assert!(out.contains("BAD No mailbox selected"), "{out:?}");
    let out = h.cmd("STORE 1 +FLAGS (\\Seen)").await;
    assert!(out.contains("BAD No mailbox selected"), "{out:?}");
    let out = h.cmd("EXPUNGE").await;
    assert!(out.contains("BAD No mailbox selected"), "{out:?}");
    let out = h.cmd("CLOSE").await;
    assert!(out.contains("BAD No mailbox selected"), "{out:?}");
    let out = h.cmd("IDLE").await;
    assert!(out.contains("BAD No mailbox selected"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_body_failure_maps_to_no_with_status_distinction() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    // ResourceExhausted → NO Server busy (retryable).
    h.mock.fail("get_message_busy");
    let out = h.cmd("FETCH 1 BODY[]").await;
    assert!(
        out.contains("NO Server busy; try again later"),
        "ResourceExhausted must map to a retryable NO: {out:?}"
    );
    h.shutdown().await;

    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.fail("get_message");
    let out = h.cmd("FETCH 1 BODY[]").await;
    assert!(
        out.contains("NO ") && !out.contains("SERVERBUSY"),
        "generic failure must be a plain NO: {out:?}"
    );
    h.shutdown().await;
}

// ── STORE ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn store_set_add_remove_and_silent() {
    let mut h = Harness::new();
    let (u1, u2) = select_two_messages(&mut h).await;

    let out = h.cmd("STORE 1 +FLAGS (\\Flagged customkw)").await;
    assert!(out.contains("* 1 FETCH (FLAGS ("), "{out:?}");
    assert!(out.contains("\\Flagged"), "{out:?}");
    assert!(
        out.contains("customkw"),
        "custom keyword round-trip: {out:?}"
    );
    assert!(out.contains("OK STORE completed, 1 updated"), "{out:?}");

    let out = h.cmd("STORE 1 -FLAGS (\\Flagged)").await;
    assert!(
        !out.contains("\\Flagged"),
        "removed flag must be gone: {out:?}"
    );
    assert!(
        out.contains("customkw"),
        "unrelated keyword survives: {out:?}"
    );

    // .SILENT echoes no FETCH.
    let out = h.cmd("STORE 1 +FLAGS.SILENT (\\Deleted)").await;
    assert!(!out.contains("FETCH"), "SILENT must not echo: {out:?}");
    assert!(out.contains("STORE completed"), "{out:?}");

    // Case-insensitive system flags (RFC 3501 flags are case-insensitive).
    let out = h.cmd("STORE 1 +FLAGS (\\seen)").await;
    assert!(out.contains("\\Seen"), "lowercase \\seen must map: {out:?}");

    // Multi-UID store.
    let out = h.cmd("UID STORE 1:2 +FLAGS (\\Answered)").await;
    assert!(out.contains("* 1 FETCH"), "{out:?}");
    assert!(out.contains("* 2 FETCH"), "{out:?}");
    assert!(out.contains("2 updated"), "{out:?}");

    // Out-of-range UID set: nothing to do, still OK (no update count is
    // emitted because no store RPC ran at all).
    let before = h.mock.recorded("set_flags").len();
    let out = h.cmd("UID STORE 999 +FLAGS (\\Seen)").await;
    assert!(out.contains("OK STORE completed"), "{out:?}");
    assert_eq!(
        h.mock.recorded("set_flags").len(),
        before,
        "an empty resolved set must not reach the store"
    );

    // A failed store is a NO, never a silent OK.
    h.mock.fail("set_flags");
    let out = h.cmd(&format!("STORE {u1} +FLAGS (\\Seen)")).await;
    assert!(out.contains("NO STORE failed"), "{out:?}");
    let _ = u2;
    h.shutdown().await;
}

#[tokio::test]
async fn store_argument_errors_are_bad() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    for cmd in ["STORE 1", "STORE 1 +FLAGS", "STORE 1:* FLAGS"] {
        let out = h.cmd(cmd).await;
        assert!(out.contains("BAD"), "{cmd}: {out:?}");
    }
    // A malformed sequence set inside STORE is a BAD.
    let out = h.cmd("STORE abc +FLAGS (\\Seen)").await;
    assert!(out.contains("BAD"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn store_never_writes_across_accounts() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.add_mailbox("acct-2", "INBOX", 9);
    h.mock.add_message(
        "acct-2",
        "INBOX",
        "foreign",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1,
    );
    let out = h.cmd("UID STORE 999 +FLAGS (\\Seen)").await;
    assert!(out.contains("OK"), "{out:?}");
    let calls = h.mock.recorded("set_flags");
    assert!(
        calls.iter().all(|c| c.ends_with("acct-1")),
        "STORE must address the session account: {calls:?}"
    );
    // And the foreign message is untouched.
    let foreign = h
        .mock
        .lock()
        .messages
        .get("acct-2")
        .unwrap()
        .get("inbox")
        .unwrap()[0]
        .clone();
    assert!(!foreign.flags.unwrap_or_default().seen);
    h.shutdown().await;
}

// ── SEARCH ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn search_criteria_and_uid_mode() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let out = h.cmd("SEARCH ALL").await;
    assert!(out.contains("* SEARCH 1 2"), "{out:?}");
    let out = h.cmd("UID SEARCH ALL").await;
    assert!(
        out.contains("* SEARCH 1 2"),
        "UID SEARCH returns UIDs: {out:?}"
    );
    let out = h.cmd("SEARCH UNSEEN").await;
    assert!(out.contains("* SEARCH 1"), "{out:?}");
    let out = h.cmd("SEARCH SEEN").await;
    assert!(out.contains("* SEARCH 2"), "{out:?}");
    let out = h.cmd("SEARCH DELETED").await;
    assert!(out.contains("* SEARCH\r\n"), "no deleted messages: {out:?}");
    let out = h.cmd("SEARCH FROM a@b").await;
    assert!(out.contains("* SEARCH 1"), "{out:?}");
    let out = h.cmd("SEARCH SUBJECT beta").await;
    assert!(out.contains("* SEARCH 2"), "{out:?}");
    let out = h.cmd("SEARCH NOT UNSEEN").await;
    assert!(
        out.contains("BAD Unsupported SEARCH criterion: NOT"),
        "NOT criteria are not implemented and must say so: {out:?}"
    );
    let out = h.cmd("SEARCH RECENT").await;
    assert!(out.contains("* SEARCH 1"), "session RECENT set: {out:?}");
    let out = h.cmd("SEARCH NEW").await;
    assert!(out.contains("* SEARCH 1"), "NEW = RECENT + UNSEEN: {out:?}");
    let out = h.cmd("SEARCH OLD").await;
    assert!(out.contains("* SEARCH 2"), "OLD is not-RECENT: {out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn search_date_flags_and_body() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    // internal_date 1000 == 1970-01-01, 2000 == same day.
    let out = h.cmd("SEARCH SINCE 01-Jan-1970").await;
    assert!(out.contains("* SEARCH 1 2"), "{out:?}");
    let out = h.cmd("SEARCH BEFORE 01-Jan-1970").await;
    assert!(out.contains("* SEARCH\r\n"), "{out:?}");
    let out = h.cmd("SEARCH ON 01-Jan-1970").await;
    assert!(out.contains("* SEARCH 1 2"), "{out:?}");
    let out = h.cmd("SEARCH SINCE notadate").await;
    assert!(out.contains("BAD Invalid date: notadate"), "{out:?}");
    // Fulltext BODY/TEXT route to the store and AND into the result.
    let out = h.cmd("SEARCH BODY alpha").await;
    assert!(out.contains("* SEARCH 1"), "store fulltext hits: {out:?}");
    // HEADER criteria use the headers search and AND.
    h.mock.lock().header_hits.insert(2);
    let out = h.cmd("SEARCH HEADER Message-ID <2@example.test>").await;
    assert!(out.contains("* SEARCH 2"), "{out:?}");
    assert_eq!(
        h.mock.recorded("subscribe_mailbox").len(),
        0,
        "no IDLE subscription from SEARCH"
    );
    let out = h.cmd("SEARCH HEADER OnlyField").await;
    assert!(
        out.contains("BAD HEADER requires a field name and a value"),
        "{out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn search_failures_are_no_not_empty_results() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.fail("search_messages");
    let out = h.cmd("SEARCH BODY alpha").await;
    assert!(
        out.contains("NO SEARCH failed"),
        "fulltext failure must NO: {out:?}"
    );
    let out = h.cmd("SEARCH HEADER From a@b").await;
    assert!(
        out.contains("NO SEARCH failed"),
        "header failure must NO: {out:?}"
    );
    h.mock.lock().fail.remove("search_messages");
    h.mock.fail("list_messages");
    let out = h.cmd("SEARCH ALL").await;
    assert!(
        out.contains("NO SEARCH failed"),
        "list failure must NO: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn search_token_bomb_is_rejected() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let bomb = std::iter::repeat_n("ALL", 70).collect::<Vec<_>>().join(" ");
    let out = h.cmd(&format!("SEARCH {bomb}")).await;
    assert!(out.contains("BAD Too many SEARCH criteria"), "{out:?}");
    h.shutdown().await;
}

// ── COPY / MOVE ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn copy_and_move_return_copyuid_and_expunge() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.add_mailbox("acct-1", "Archive", 500);

    let out = h.cmd("COPY 1 Archive").await;
    assert!(
        out.contains("OK [COPYUID 500 1 1] COPY completed"),
        "{out:?}"
    );
    assert_eq!(h.mock.message_uids("acct-1", "Archive"), vec![1]);

    let out = h.cmd("UID MOVE 2 Archive").await;
    assert!(
        out.contains("* 2 EXPUNGE"),
        "MOVE must EXPUNGE locally: {out:?}"
    );
    assert!(
        out.contains("OK [COPYUID 500 2 2] MOVE completed"),
        "{out:?}"
    );
    assert_eq!(h.mock.message_uids("acct-1", "INBOX"), vec![1]);
    let s = h.session.lock().await;
    assert_eq!(s.uid_map, vec![1]);
    assert_eq!(s.exists, 1);
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn copy_move_to_missing_mailbox_is_no_trycreate() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let out = h.cmd("COPY 1 Nope").await;
    assert!(
        out.contains("NO [TRYCREATE] Destination mailbox does not exist"),
        "{out:?}"
    );
    let out = h.cmd("MOVE 1 Nope").await;
    assert!(out.contains("NO [TRYCREATE]"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn copy_argument_and_out_of_range_cases() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.add_mailbox("acct-1", "Archive", 500);

    let out = h.cmd("COPY 1").await;
    assert!(out.contains("BAD COPY/MOVE requires"), "{out:?}");
    let out = h.cmd("COPY 99 Archive").await;
    assert!(out.contains("OK COPY completed"), "no-op range: {out:?}");
    assert!(h.mock.message_uids("acct-1", "Archive").is_empty());

    // The destination may be quoted / a literal; the name is IMAP-UTF-7.
    let out = h.cmd("COPY 1 \"Archive\"").await;
    assert!(out.contains("COPY completed"), "{out:?}");
    // Cross-tenant destination: acct-2's Archive must not be found.
    h.mock.add_mailbox("acct-2", "Other", 1);
    let out = h.cmd("COPY 1 Other").await;
    assert!(
        out.contains("NO [TRYCREATE]"),
        "foreign mailbox must not resolve: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn copy_transport_failure_is_no() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.add_mailbox("acct-1", "Archive", 500);
    h.mock.fail("copy_message");
    let out = h.cmd("COPY 1 Archive").await;
    assert!(out.contains("NO COPY failed"), "{out:?}");
    h.mock.lock().fail.remove("copy_message");
    h.mock.fail("move_message");
    let out = h.cmd("MOVE 1 Archive").await;
    assert!(out.contains("NO MOVE failed"), "{out:?}");
    // The session view must be untouched by a failed MOVE.
    assert_eq!(h.session.lock().await.uid_map, vec![1, 2]);
    h.shutdown().await;
}

// ── CREATE / DELETE / RENAME ────────────────────────────────────────────────

#[tokio::test]
async fn create_delete_round_trip_and_failures() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("CREATE Projects").await;
    assert!(
        out.contains("OK CREATE completed, mailbox Projects"),
        "{out:?}"
    );
    assert!(h.mock.mailbox_row("acct-1", "Projects").is_some());
    assert_eq!(h.mock.recorded("create_mailbox"), vec!["Projects"]);

    let out = h.cmd("DELETE Projects").await;
    assert!(
        out.contains("OK DELETE completed, mailbox Projects"),
        "{out:?}"
    );
    assert!(h.mock.mailbox_row("acct-1", "Projects").is_none());

    // Missing argument is BAD, not a create of the empty name.
    let out = h.cmd("CREATE").await;
    assert!(out.contains("BAD Mailbox name required"), "{out:?}");
    let out = h.cmd("DELETE").await;
    assert!(out.contains("BAD Mailbox name required"), "{out:?}");

    // A store failure surfaces as NO (never a false OK).
    h.mock.fail("create_mailbox");
    let out = h.cmd("CREATE Broken").await;
    assert!(out.contains("NO CREATE failed"), "{out:?}");
    h.mock.lock().fail.remove("create_mailbox");
    h.mock.fail("delete_mailbox");
    let out = h.cmd("DELETE Projects").await;
    assert!(out.contains("NO DELETE failed"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn rename_moves_messages_and_deletes_source() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.add_mailbox("acct-1", "Old", 31);
    h.mock.add_mailbox("acct-1", "New", 32);
    h.mock.add_message(
        "acct-1",
        "Old",
        "x",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1,
    );
    h.mock.add_message(
        "acct-1",
        "Old",
        "y",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        2,
    );

    let out = h.cmd("RENAME Old New").await;
    assert!(out.contains("OK RENAME completed Old -> New"), "{out:?}");
    assert!(h.mock.message_uids("acct-1", "Old").is_empty());
    assert_eq!(h.mock.message_uids("acct-1", "New").len(), 2);
    assert!(h.mock.mailbox_row("acct-1", "Old").is_none());
    h.shutdown().await;
}

#[tokio::test]
async fn rename_inbox_keeps_inbox_but_moves_messages() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.add_mailbox("acct-1", "Moved", 44);
    let out = h.cmd("RENAME INBOX Moved").await;
    assert!(
        out.contains("OK RENAME completed INBOX -> Moved"),
        "{out:?}"
    );
    assert!(
        h.mock.mailbox_row("acct-1", "INBOX").is_some(),
        "RFC 3501 §6.3.5: INBOX stays after RENAME"
    );
    assert!(h.mock.message_uids("acct-1", "INBOX").is_empty());
    assert_eq!(h.mock.message_uids("acct-1", "Moved").len(), 2);
    h.shutdown().await;
}

#[tokio::test]
async fn rename_argument_errors_and_store_failures() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("RENAME OnlyOne").await;
    assert!(
        out.contains("BAD RENAME requires old and new name"),
        "{out:?}"
    );
    let out = h.cmd("RENAME A").await;
    assert!(out.contains("BAD RENAME requires"), "{out:?}");

    h.mock.fail("create_mailbox");
    let out = h.cmd("RENAME A B").await;
    assert!(out.contains("NO RENAME failed"), "{out:?}");
    h.mock.lock().fail.remove("create_mailbox");

    // Source listing failure must abort before any delete.
    h.mock.add_mailbox("acct-1", "Src", 1);
    h.mock.add_message(
        "acct-1",
        "Src",
        "keep",
        "a@b.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        1,
    );
    h.mock.fail("list_messages");
    let out = h.cmd("RENAME Src Dst").await;
    assert!(
        out.contains("NO RENAME failed: could not list source mailbox"),
        "{out:?}"
    );
    assert!(
        h.mock.mailbox_row("acct-1", "Src").is_some(),
        "source must survive"
    );
    h.shutdown().await;
}

// ── APPEND ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn append_stores_exactly_once_and_reports_appenduid() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1234);
    h.select("INBOX").await;

    let out = h
        .cmd_with_literal(
            "APPEND INBOX (\\Seen) \"01-Jan-2020 10:00:00 +0000\" ",
            b"Subject: hi\r\n\r\nbody",
            "",
        )
        .await;
    assert!(
        out.contains("* 1 EXISTS"),
        "selected mailbox view updates: {out:?}"
    );
    assert!(
        out.contains("OK [APPENDUID 1234 1] APPEND completed"),
        "{out:?}"
    );
    assert_eq!(
        h.mock.recorded("store_message").len(),
        1,
        "exactly one store RPC: {:?}",
        h.mock.recorded("store_message")
    );
    assert_eq!(h.mock.message_uids("acct-1", "INBOX"), vec![1]);
    // The stored internal date is the explicit one.
    let meta = h.mock.lock().messages["acct-1"]["inbox"][0].clone();
    assert_eq!(
        meta.internal_date,
        chrono::DateTime::parse_from_rfc2822("Wed, 1 Jan 2020 10:00:00 +0000")
            .unwrap()
            .timestamp()
    );
    let s = h.session.lock().await;
    assert_eq!(s.uid_map, vec![1]);
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn append_errors_map_to_rfc3501_codes() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    // Nonexistent mailbox → NO [TRYCREATE].
    let out = h.cmd_with_literal("APPEND Ghost ", b"data", "").await;
    assert!(
        out.contains("NO [TRYCREATE] Mailbox does not exist"),
        "{out:?}"
    );

    // Quota refusal → NO [ALERT].
    h.mock.add_mailbox("acct-1", "INBOX", 7);
    h.mock.fail("quota");
    let out = h.cmd_with_literal("APPEND INBOX ", b"data", "").await;
    assert!(out.contains("NO [ALERT] Quota exceeded"), "{out:?}");
    assert!(h.mock.message_uids("acct-1", "INBOX").is_empty());
    h.mock.lock().fail.remove("quota");

    // Generic store failure → NO APPEND failed.
    h.mock.fail("store_message");
    let out = h.cmd_with_literal("APPEND INBOX ", b"data", "").await;
    assert!(out.contains("NO APPEND failed"), "{out:?}");

    // Extra argument after the literal → BAD.
    let out = h.cmd_with_literal("APPEND INBOX ", b"data", " extra").await;
    assert!(out.contains("BAD Unexpected extra argument"), "{out:?}");

    // Invalid date-time → BAD, nothing stored.
    let out = h
        .cmd_with_literal("APPEND INBOX \"not a date\" ", b"data", "")
        .await;
    assert!(out.contains("BAD Invalid date-time"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn append_missing_literal_is_bad_and_no_args_is_bad() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 7);
    let out = h.cmd("APPEND").await;
    assert!(out.contains("BAD APPEND requires a mailbox"), "{out:?}");
    let out = h.cmd("APPEND INBOX").await;
    assert!(
        out.contains("BAD APPEND requires a literal message"),
        "{out:?}"
    );
    let out = h.cmd("APPEND INBOX (\\Seen)").await;
    assert!(
        out.contains("BAD APPEND requires a literal message"),
        "{out:?}"
    );
    assert!(h.mock.message_uids("acct-1", "INBOX").is_empty());
    h.shutdown().await;
}

#[tokio::test]
async fn oversized_literal_is_refused_without_reading_the_payload() {
    let mut h = Harness::with_policy("127.0.0.1", false, true);
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 7);
    // 33 MiB > MAX_LITERAL_SIZE (32 MiB): the server must refuse to read it
    // and close, never allocating or consuming the declared size.
    h.send_line("A900 APPEND INBOX {34603009}").await;
    // The connection must be closed without a continuation request.
    let mut buf = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut buf))
        .await
        .expect("server must close, not hang")
        .expect("read");
    assert_eq!(
        n,
        0,
        "expected EOF, got {:?}",
        String::from_utf8_lossy(&buf)
    );
    assert!(
        !buf.starts_with(b"+"),
        "no continuation for over-budget literal"
    );
    assert!(h.mock.message_uids("acct-1", "INBOX").is_empty());
}

#[tokio::test]
async fn truncated_literal_closes_connection_without_executing() {
    let mut h = Harness::with_policy("127.0.0.1", false, true);
    h.login("user@example.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 7);
    // Declare 100 bytes, send 5, then close the write side.
    h.send_line("A900 APPEND INBOX {100}").await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert!(cont.starts_with(b"+"), "{cont:?}");
    h.send_raw(b"short").await;
    drop(h.io); // close the client side mid-literal
                // The server must not store a truncated message.
    let server = h.server;
    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
    assert!(
        h.mock.message_uids("acct-1", "INBOX").is_empty(),
        "no partial APPEND may reach the store"
    );
}

#[tokio::test]
async fn non_synchronizing_literal_needs_no_continuation() {
    let mut h = Harness::with_policy("127.0.0.1", false, true);
    h.mock.add_account("ns@example.test", "acct-1", "pw");
    h.mock.add_mailbox("acct-1", "INBOX", 8);
    // LITERAL+ ({n+}): the client sends the octets immediately.
    h.read_greeting().await;
    let tag = h.fresh_tag();
    h.send_raw(format!("{tag} LOGIN {{15+}}\r\n").as_bytes())
        .await;
    h.send_raw(b"ns@example.test").await;
    h.send_line(" pw").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(
        out.contains("OK LOGIN succeeded"),
        "no continuation needed: {out:?}"
    );
    h.shutdown().await;
}

// ── EXPUNGE / CLOSE / NOOP ──────────────────────────────────────────────────

#[tokio::test]
async fn expunge_removes_deleted_and_renumbers() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.cmd("STORE 1 +FLAGS (\\Deleted)").await;
    let out = h.cmd("EXPUNGE").await;
    assert!(out.contains("* 1 EXPUNGE"), "{out:?}");
    assert!(out.contains("* 1 EXISTS"), "{out:?}");
    assert!(out.contains("OK EXPUNGE completed"), "{out:?}");
    assert_eq!(h.mock.message_uids("acct-1", "INBOX"), vec![2]);
    let s = h.session.lock().await;
    assert_eq!(s.uid_map, vec![2]);
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn uid_expunge_only_removes_the_requested_deleted_uids() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.cmd("STORE 1:2 +FLAGS (\\Deleted)").await;
    let out = h.cmd("UID EXPUNGE 2").await;
    assert!(out.contains("* 2 EXPUNGE"), "{out:?}");
    assert!(!out.contains("EXPUNGE\r\n*A004 OK"), "{out:?}");
    assert!(out.contains("OK EXPUNGE completed"), "{out:?}");
    assert_eq!(h.mock.message_uids("acct-1", "INBOX"), vec![1]);

    // A UID set that resolves to nothing expunges nothing.
    let out = h.cmd("UID EXPUNGE 999").await;
    assert!(out.contains("OK EXPUNGE completed"), "{out:?}");
    assert_eq!(h.mock.message_uids("acct-1", "INBOX"), vec![1]);

    // Malformed UID set is BAD.
    let out = h.cmd("UID EXPUNGE abc").await;
    assert!(out.contains("BAD"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn expunge_failure_is_no_and_view_survives() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.fail("expunge");
    let out = h.cmd("EXPUNGE").await;
    assert!(out.contains("NO EXPUNGE failed"), "{out:?}");
    assert_eq!(h.session.lock().await.uid_map, vec![1, 2]);
    h.shutdown().await;
}

#[tokio::test]
async fn close_expunges_then_deselects() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.cmd("STORE 1 +FLAGS.SILENT (\\Deleted)").await;
    let out = h.cmd("CLOSE").await;
    assert!(
        out.contains("OK CLOSE completed"),
        "CLOSE is silent: {out:?}"
    );
    assert!(
        !out.contains("EXPUNGE"),
        "CLOSE reports no EXPUNGE: {out:?}"
    );
    let s = h.session.lock().await;
    assert_eq!(s.state, SessionState::Authenticated);
    assert!(s.mailbox.is_empty());
    drop(s);
    assert_eq!(h.mock.message_uids("acct-1", "INBOX"), vec![2]);
    h.shutdown().await;
}

#[tokio::test]
async fn close_expunge_failure_is_no_and_stays_selected() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    h.mock.fail("expunge");
    let out = h.cmd("CLOSE").await;
    assert!(out.contains("NO CLOSE failed: expunge error"), "{out:?}");
    let s = h.session.lock().await;
    assert_eq!(
        s.state,
        SessionState::Selected,
        "a failed CLOSE must not deselect"
    );
    drop(s);
    h.shutdown().await;
}

#[tokio::test]
async fn noop_detects_arrivals_and_expunges_from_other_sessions() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    // Another session appends a message: uidnext/exists change.
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "new",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        5000,
    );
    let out = h.noop().await;
    assert!(out.contains("* 3 EXISTS"), "{out:?}");
    assert!(out.contains("OK [UIDNEXT 4]"), "{out:?}");
    // uids 1 (unseen) and 3 (unseen arrival) are session-RECENT; uid 2 is seen.
    assert!(
        out.contains("* 2 RECENT"),
        "unseen arrival joins RECENT: {out:?}"
    );

    // Another session expunges message 1: NOOP must report the EXPUNGE.
    {
        let mut g = h.mock.lock();
        g.messages
            .get_mut("acct-1")
            .unwrap()
            .get_mut("inbox")
            .unwrap()
            .remove(0);
    }
    let out = h.noop().await;
    assert!(out.contains("* 1 EXPUNGE"), "{out:?}");
    assert!(out.contains("* 2 EXISTS"), "{out:?}");

    // An unchanged mailbox produces no unsolicited noise.
    let out = h.noop().await;
    assert_eq!(out.trim_end().lines().count(), 1, "no-change NOOP: {out:?}");
    assert!(out.contains("OK NOOP completed"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn noop_without_selection_is_silent_and_ok() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("NOOP").await;
    assert!(out.contains("OK NOOP completed"), "{out:?}");
    let out = h.cmd("CHECK").await;
    assert!(
        out.contains("OK NOOP completed"),
        "CHECK aliases NOOP: {out:?}"
    );
    h.shutdown().await;
}

// ── IDLE ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn idle_done_round_trip() {
    let mut h = Harness::new();
    h.read_greeting().await;
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&cont), "+ idling\r\n");
    assert!(h.session.lock().await.idle);

    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("OK IDLE terminated"), "{out:?}");
    assert!(
        !h.session.lock().await.idle,
        "IDLE state cleared after DONE"
    );

    // The session is usable again.
    let out = h.cmd("NOOP").await;
    assert!(out.contains("OK NOOP completed"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn idle_disconnect_ends_the_session_without_leaking_state() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert!(cont.starts_with(b"+"));

    // Client vanishes while idling: the server must mark the session Logout
    // and finish the connection task (no task leak).
    drop(h.io);
    let server = h.server;
    let res = tokio::time::timeout(Duration::from_secs(10), server).await;
    assert!(res.is_ok(), "serve task must finish on IDLE disconnect");
    let _ = res.unwrap();
}

#[tokio::test]
async fn idle_command_abuse_and_logout() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;

    // A non-DONE command while idling → BAD, IDLE continues.
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    h.send_line("B001 FETCH 1 UID").await;
    let mut resp = Vec::new();
    h.io.read_until(b'\n', &mut resp).await.unwrap();
    assert!(
        String::from_utf8_lossy(&resp).contains("BAD Command not allowed during IDLE"),
        "{resp:?}"
    );
    assert!(h.session.lock().await.idle, "IDLE continues after BAD");

    // LOGOUT while idling terminates the session and the task.
    h.send_line("B002 LOGOUT").await;
    let mut all = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut line))
            .await
            .expect("logout response")
            .expect("read");
        if n == 0 {
            break;
        }
        all.extend_from_slice(&line);
        if line.starts_with(b"B002 OK") {
            break;
        }
    }
    let all = String::from_utf8_lossy(&all);
    assert!(all.contains("* BYE Logging out"), "{all:?}");
    assert!(all.contains("B002 OK LOGOUT completed"), "{all:?}");
    let res = tokio::time::timeout(Duration::from_secs(10), h.server).await;
    assert!(res.is_ok(), "serve task must end after IDLE LOGOUT");
}

#[tokio::test]
async fn idle_emits_unsolicited_exists_on_mailbox_events() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert!(cont.starts_with(b"+"), "{cont:?}");

    // Wait until the mock has registered the subscription, then push an
    // event (the real mailstore stream does exactly this).
    let sender = loop {
        let calls = h.mock.recorded("subscribe_mailbox");
        if !calls.is_empty() {
            break h.mock.events_sender("acct-1", "INBOX");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let new_uid = h.mock.add_message(
        "acct-1",
        "INBOX",
        "pushed",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        9000,
    );
    sender
        .send(MailboxEvent {
            event: Some(mail_proto::mailbox_event::Event::MailboxUpdated(
                mail_proto::MailboxUpdated {
                    mailbox: Some(mail_proto::Mailbox {
                        name: "INBOX".to_string(),
                        uidnext: new_uid + 1,
                        exists: 3,
                        ..Default::default()
                    }),
                },
            )),
        })
        .expect("event send");

    // Expect an unsolicited EXISTS line before DONE's OK.
    let mut seen_exists = false;
    for _ in 0..5 {
        let mut line = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut line))
            .await
            .expect("unsolicited update")
            .expect("read");
        if n == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        if text.starts_with("* 3 EXISTS") {
            seen_exists = true;
            break;
        }
    }
    assert!(seen_exists, "IDLE must emit an unsolicited EXISTS");

    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("OK IDLE terminated"), "{out:?}");
    assert_eq!(h.session.lock().await.exists, 3);
    h.shutdown().await;
}

// ── auth throttling ─────────────────────────────────────────────────────────

#[tokio::test]
async fn failed_logins_lock_the_pair_and_lockout_is_per_account_and_ip() {
    let ip = format!("10.77.77.77:{}", std::process::id());
    let mut h = Harness::with_session(&ip, true, false, true);
    h.mock.add_account("victim@example.test", "acct-1", "right");

    for i in 0..5 {
        let out = h.cmd("LOGIN victim@example.test wrong").await;
        assert!(out.contains("NO LOGIN failed"), "attempt {i}: {out:?}");
    }
    // RFC 3501 allows a temporary NO; the exact code is [AUTHORIZATIONFAILED].
    let out = h.cmd("LOGIN victim@example.test right").await;
    assert!(
        out.contains("NO [AUTHORIZATIONFAILED] Too many failed attempts"),
        "correct password must still be locked out: {out:?}"
    );
    // Another account from the same IP is unaffected.
    h.mock.add_account("other@example.test", "acct-2", "pw2");
    let out = h.cmd("LOGIN other@example.test pw2").await;
    assert!(
        out.contains("OK LOGIN succeeded"),
        "per-account lockout: {out:?}"
    );

    // A successful login cleared the previous pair's counter.
    let out = h.cmd("NOOP").await;
    assert!(out.contains("OK"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn authenticate_plain_over_tls_success_and_failure() {
    let mut h = Harness::new();
    h.mock.add_account("ap@example.test", "acct-1", "pw");
    let b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"\0ap@example.test\0pw")
    };
    let out = h.cmd(&format!("AUTHENTICATE PLAIN {b64}")).await;
    assert!(out.contains("OK"), "{out:?}");
    assert_eq!(h.session.lock().await.account_id, "acct-1");

    // Wrong password → NO, and the session stays unauthenticated.
    let mut h = Harness::new();
    h.mock.add_account("ap@example.test", "acct-1", "pw");
    let bad = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"\0ap@example.test\0bad")
    };
    let out = h.cmd(&format!("AUTHENTICATE PLAIN {bad}")).await;
    assert!(out.contains("NO"), "{out:?}");
    assert_eq!(h.session.lock().await.state, SessionState::NotAuthenticated);
    h.shutdown().await;
}

#[tokio::test]
async fn authenticate_plain_two_step_with_star_cancel() {
    let mut h = Harness::new();
    h.mock.add_account("two@example.test", "acct-1", "pw");
    h.read_greeting().await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} AUTHENTICATE PLAIN")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert!(cont.starts_with(b"+"), "continuation expected: {cont:?}");
    h.send_line("*").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(
        out.contains("BAD") || out.contains("NO"),
        "cancel must fail: {out:?}"
    );
    assert_eq!(h.session.lock().await.state, SessionState::NotAuthenticated);
    h.shutdown().await;
}

#[tokio::test]
async fn authenticate_unsupported_mechanism_is_no() {
    let mut h = Harness::new();
    let out = h.cmd("AUTHENTICATE CRAM-MD5").await;
    assert!(out.contains("NO"), "unsupported mechanism: {out:?}");
    let out = h.cmd("AUTHENTICATE").await;
    assert!(out.contains("BAD") || out.contains("NO"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn logout_sends_bye_and_ends_the_task() {
    let mut h = Harness::new();
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} LOGOUT")).await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("* BYE Logging out"), "{out:?}");
    assert!(out.contains("OK LOGOUT completed"), "{out:?}");
    let res = tokio::time::timeout(Duration::from_secs(10), h.server).await;
    assert!(res.is_ok(), "serve task ends after LOGOUT");
}

#[tokio::test]
async fn hostile_utf7_mailbox_names_never_inject_response_lines() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    // A literal mailbox name carrying CRLF and quotes: CREATE passes it
    // through to the store, and the OK line must escape it, not split.
    let out = h
        .cmd_with_literal("CREATE ", b"Evil\"\r\nInjected", "")
        .await;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "a CRLF in the name must not split the response: {out:?}"
    );
    assert!(out.contains("OK"), "{out:?}");
    assert!(!out.contains("Injected\r\n"), "{out:?}");

    // Unicode / imap-utf7 round trip through CREATE.
    let out = h.cmd("CREATE \"&AOk-\"").await; // "ü" in mUTF-7
    assert!(out.contains("OK"), "{out:?}");
    let created = h.mock.recorded("create_mailbox");
    assert!(
        created.iter().any(|n| n == "é"),
        "mUTF-7 &AOk- decodes to é: {created:?}"
    );
    h.shutdown().await;
}

// ── NAMESPACE / AUTHENTICATE continuation ───────────────────────────────────

#[tokio::test]
async fn namespace_reports_the_personal_namespace() {
    let mut h = Harness::new();
    h.login("user@example.test", "pw").await;
    let out = h.cmd("NAMESPACE").await;
    assert!(
        out.contains("* NAMESPACE ((\"\" \"/\")) NIL NIL"),
        "{out:?}"
    );
    assert!(out.contains("OK NAMESPACE completed"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn authenticate_policy_and_state_gates() {
    // Plaintext, insecure auth not allowed → [PRIVACYREQUIRED].
    let mut h = Harness::with_session("10.1.1.1", false, false, true);
    h.mock.add_account("x@example.test", "acct-1", "pw");
    h.read_greeting().await;
    let out = h.cmd("AUTHENTICATE PLAIN AGFiYw==").await;
    assert!(
        out.contains("NO [PRIVACYREQUIRED] AUTHENTICATE requires a TLS connection"),
        "{out:?}"
    );
    assert!(h.mock.recorded("authenticate_account").is_empty());

    // Already authenticated → BAD (RFC 3501 §6.2.2).
    let mut h = Harness::with_session("10.1.1.2", true, false, true);
    h.read_greeting().await;
    h.login("x@example.test", "pw").await;
    let out = h.cmd("AUTHENTICATE PLAIN").await;
    assert!(out.contains("BAD Already authenticated"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn authenticate_continuation_flow_errors() {
    // Unknown mechanism → NO, no continuation.
    let mut h = Harness::new();
    h.read_greeting().await;
    let out = h.cmd("AUTHENTICATE CRAM-MD5").await;
    assert!(
        out.contains("NO Unsupported AUTH mechanism: CRAM-MD5"),
        "{out:?}"
    );

    // Continuation prompt then bad base64 → BAD.
    let mut h = Harness::new();
    h.read_greeting().await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} AUTHENTICATE PLAIN")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&cont), "+ \r\n");
    h.send_line("!!!not-base64!!!").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(
        out.contains("BAD Invalid base64 in AUTHENTICATE"),
        "{out:?}"
    );

    // Valid base64 but no NUL separators → BAD invalid payload.
    let mut h = Harness::new();
    h.read_greeting().await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} AUTHENTICATE PLAIN")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    let b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"noNULseparators")
    };
    h.send_line(&b64).await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("BAD Invalid AUTHENTICATE payload"), "{out:?}");

    // SASL-IR with the empty response ("=") is an empty payload: the
    // exchange ends as a cancelled BAD, never a crash or a hang.
    let mut h = Harness::new();
    h.read_greeting().await;
    let out = h.cmd("AUTHENTICATE PLAIN =").await;
    assert!(
        out.contains("BAD AUTHENTICATE cancelled"),
        "an empty payload is rejected: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn authenticate_lockout_after_repeated_failures() {
    let ip = format!("10.42.42.42:{}", std::process::id());
    let mut h = Harness::with_session(&ip, true, false, true);
    h.mock.add_account("lock@example.test", "acct-1", "right");
    h.read_greeting().await;
    let bad = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"\0lock@example.test\0bad")
    };
    for i in 0..AUTH_FAILURE_LIMIT {
        let out = h.cmd(&format!("AUTHENTICATE PLAIN {bad}")).await;
        assert!(out.contains("NO"), "attempt {i}: {out:?}");
    }
    let good = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"\0lock@example.test\0right")
    };
    let out = h.cmd(&format!("AUTHENTICATE PLAIN {good}")).await;
    assert!(
        out.contains("NO [AUTHORIZATIONFAILED] Too many failed attempts"),
        "correct credentials must still be throttled: {out:?}"
    );
    assert_eq!(h.session.lock().await.state, SessionState::NotAuthenticated);
    h.shutdown().await;
}

// ── IDLE runtime details ────────────────────────────────────────────────────

#[tokio::test]
async fn idle_event_with_unchanged_snapshot_emits_nothing() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    assert!(cont.starts_with(b"+"));

    let sender = loop {
        if !h.mock.recorded("subscribe_mailbox").is_empty() {
            break h.mock.events_sender("acct-1", "INBOX");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    // Flag-only events do not change uidnext/exists/modseq: the cost gate
    // must keep the session silent.
    sender
        .send(MailboxEvent {
            event: Some(mail_proto::mailbox_event::Event::FlagsChanged(
                mail_proto::FlagsChanged {
                    uid: 1,
                    flags: Some(mail_proto::MessageFlags {
                        seen: true,
                        ..Default::default()
                    }),
                },
            )),
        })
        .unwrap();
    // DONE is the next thing the server must produce.
    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert_eq!(
        out.lines().count(),
        1,
        "a no-op IDLE event must not produce unsolicited lines: {out:?}"
    );
    assert!(out.contains("OK IDLE terminated"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn idle_event_when_store_listing_fails_is_survivable() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    let sender = loop {
        if !h.mock.recorded("subscribe_mailbox").is_empty() {
            break h.mock.events_sender("acct-1", "INBOX");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    // A change that forces the refresh, while the listing RPC fails.
    h.mock.fail("list_messages");
    h.mock.add_message(
        "acct-1",
        "INBOX",
        "arrival",
        "x@y.test",
        mail_proto::MessageFlags {
            seen: false,
            deleted: false,
            ..Default::default()
        },
        7000,
    );
    sender
        .send(MailboxEvent {
            event: Some(mail_proto::mailbox_event::Event::MessageAdded(
                mail_proto::MessageAdded {
                    message: Some(mail_proto::MessageMeta {
                        uid: 3,
                        ..Default::default()
                    }),
                },
            )),
        })
        .unwrap();
    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(
        out.contains("OK IDLE terminated"),
        "a failed refresh must not kill IDLE: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn idle_event_stream_end_then_done_still_works() {
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.unwrap();
    let sender = loop {
        if !h.mock.recorded("subscribe_mailbox").is_empty() {
            break h.mock.events_sender("acct-1", "INBOX");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    // The mailstore stream ends: the session must fall back to waiting for
    // DONE only.
    drop(sender);
    // Give the runtime a moment to observe the closed stream.
    tokio::time::sleep(Duration::from_millis(20)).await;
    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(
        out.contains("OK IDLE terminated"),
        "a dead event stream must not break DONE: {out:?}"
    );
    h.shutdown().await;
}

// ── configure_tls ───────────────────────────────────────────────────────────

/// Self-signed test certificate/key pair (test-only material, generated
/// once for the crate's TLS tests). Embedded so the test is hermetic: no
/// fixture path can be missing at runtime.
const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUVwhxJa9wz86lWTzyVQVC9bHNeXUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwOTE5MjIxMVoXDTM2MDgw
NjE5MjIxMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA6qhnhEk3kzT8KOzUcXhTbsoxnYx7zXwW8UPFQ4bshey8
Elbk3+cJBbwsknhHIebiJ8ZcaOqdzJk+5iv/fyGfE6BEGn+CEWvGMp+N3M3TmEsA
hph9mYlSeDlwv0j3+0KUBnLa9yM3MIuZYHglll+NVpc3yEo8DtVp0qNRvyykxojO
t2lB9/BZRBY4ReKIfw97HAjsM2iJ6DSUFNi0Gj1KYdRts8YeYsnzavjFT+DtmJeL
v8xejwba10wJCsajtdS+iL3rGw+szNaWshvdSEA3ZEqEqBwyJnch6gxDAGWwmjOQ
aLDg+VPTBqxlXQx2Igygf/AkAZuP893RUEYwLO9BwQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBS7l0LAXjJdC3qid0GAZlqF97CDzzAfBgNVHSMEGDAWgBS7l0LAXjJdC3qi
d0GAZlqF97CDzzAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAN7qZaPKPucQtxzwLQAgAGNmJbTpbszbNUv/eUvxLSOQuaQf
GO2K6KNKgDPt1E0jN6hpuJHY86G2wjxW3g4i+IUrHsv8dP+qOHDOG2SknYfxagph
ekb7NYuL/SpggUljQQD26flq7dpV7RXdL1q4XFHoHFjQIvNEZjyg0cDheAcwXdig
YzD9bl7yCpnvXHy4p7G0SYXAYkK8DG5FcS/ECTJw/gjMEDsIPLqPHNsC2uaq+C0R
fwY+YpZkXTmxfHPbSn0EKcbKj1lHFsvSm9ckfUjEJV5vcIk5+TewmU4cEzQloK9v
MpuYqjOkD826HkH+KCOEK4qVsx1p1MM0ASjES0E=
-----END CERTIFICATE-----"#;
const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqqGeESTeTNPwo
7NRxeFNuyjGdjHvNfBbxQ8VDhuyF7LwSVuTf5wkFvCySeEch5uInxlxo6p3MmT7m
K/9/IZ8ToEQaf4IRa8Yyn43czdOYSwCGmH2ZiVJ4OXC/SPf7QpQGctr3Izcwi5lg
eCWWX41WlzfISjwO1WnSo1G/LKTGiM63aUH38FlEFjhF4oh/D3scCOwzaInoNJQU
2LQaPUph1G2zxh5iyfNq+MVP4O2Yl4u/zF6PBtrXTAkKxqO11L6IvesbD6zM1pay
G91IQDdkSoSoHDImdyHqDEMAZbCaM5BosOD5U9MGrGVdDHYiDKB/8CQBm4/z3dFQ
RjAs70HBAgMBAAECggEAAXIkUaUJGPDLEzY63KBf/Ls1lS2++0oWAtpu3Cq4GT7n
PYJwLnZAKKszN9uSfiGr3/B9pCaabm7dC6pmnI4cqqB6nPJvTuvL5MbVhyBUSwBe
zmWBBB27zqp1cLNKll9vla7WXS6YDeY1Taot2pxn/LoprYPyFOoRGOt5UukLsp61
CIIljP/VXW+OdAZMVBSLDDoJTbs5Hiyr/KlZ5v6ABun8wFUrkZfiDqCgzZO2+dWP
+hGmwSfBdufB+tSpPjsNIWpezrcfRpK3AVz8aiesuacxu99wTwY/0qjpbKPwucqT
G4HlQ4ZitA6m2SJUXw/E+Ij7ziT1UZzx8ltRrMrDQQKBgQD5oaWTnlAk4BJmcPUp
G7uA7uanr6r3vNR6awTn5tvqoOcDrWSWzM3YzBFD0Z4vWNDcLAB8TacCyIjQwxFl
cP3hNdhO5r0IuoIoJkbrcGeVPNoEJ0xNDpCAFrzi2CS27vqc518BSBhXgtPNMC7B
cOosHobInSi/rIgZPTPjGU8J4QKBgQDwpPbgEBSzfKuSYnUX0+/Zg9BZWEIBVd1x
Ny8B6GXCOuA75lYuTuSrylTyfCZCwTzXMhXuWAgpvHHoiyKYAL1vjSQmv8JDRO79
DtQsl8yqB3nEGJM8pHveEcO7kpEtMIUM+E3HfmvLvzaFDfd/HL0oyUBAP8oLtOG/
A+LaYPfz4QKBgQD3ybHOhv3srJL3Jrbj2EhV4k4IM0JU6RZMccCL5Md07cSCDPJl
EeReh6m3lPIc819WvUK6IGZgR+guuQKim/cWPtl48GbBrEiYS+5ns8rOA3oxV0TQ
1F0xF+Dkl0JSZ4NSjgPrBMJM02skKOiwUUHRC3gk2INjR4JM80h2619eYQKBgGGM
HV76ZcnUMaBnNNvx13ouyphNBISSD+/C1NVLJWS0hQ0C89BVvrA8lm6tEL1io40A
Co/RM43ni60eKWnAcwnzBsKGXPLz0ITYK/3fkuEhoqRw6c5dRrDgNp2kbiEJWAXH
6Y+CmaO/4RPSc48dUThlTBw/P2G7cv8BTkYDpL9BAoGAOnK0/9XWEoUAjVlPJnZh
RSWoMFYTY/7nu3u6377ccMjpQkaZLMb0y8uI+LYAlKJ+LN+ORNxS9LeGv3jHCRuL
++Z2Nalu581oXeFgZM/i7pCe0bdvqZ0xQZpQA5hJ0qDAYDvM098UF30cMS6NiGoP
KihCoEUsqFfVk4/gsIHZAN0=
-----END PRIVATE KEY-----"#;

#[tokio::test]
async fn configure_tls_loads_a_real_pair_and_refuses_broken_inputs() {
    // Same provider the binary installs at startup (idempotent).
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    let dir = std::env::temp_dir().join(format!("imap-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, TEST_CERT_PEM).unwrap();
    std::fs::write(&key, TEST_KEY_PEM).unwrap();
    let cert = cert.to_str().unwrap();
    let key = key.to_str().unwrap();

    let acceptor = configure_tls(Some(cert), Some(key)).expect("valid pair loads");
    assert!(acceptor.is_some(), "a valid cert+key yields an acceptor");

    // Missing files are hard errors, not silent None. (TlsAcceptor is not
    // Debug, so match instead of unwrap_err.)
    let err = match configure_tls(Some("/nonexistent/cert.pem"), Some(key)) {
        Err(error) => error,
        Ok(_) => panic!("a missing cert file must be an error"),
    };
    assert!(
        format!("{err:#}").contains("Failed to open cert file"),
        "{err:#}"
    );
    let err = match configure_tls(Some(cert), Some("/nonexistent/key.pem")) {
        Err(error) => error,
        Ok(_) => panic!("a missing key file must be an error"),
    };
    assert!(
        format!("{err:#}").contains("Failed to open key file"),
        "{err:#}"
    );

    // A file without PEM blocks: certs() yields an empty list → rustls
    // rejects the empty certificate chain.
    let empty = dir.join("empty.pem");
    std::fs::write(&empty, b"not a pem at all\n").unwrap();
    let err = match configure_tls(Some(empty.to_str().unwrap()), Some(key)) {
        Err(error) => error,
        Ok(_) => panic!("a PEM with no certificates must be an error"),
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("Failed to build TLS server config") || text.contains("Failed to read certs"),
        "{text}"
    );

    // A key file with no private key → explicit "No private key found".
    let nokey = dir.join("nokey.pem");
    std::fs::write(
        &nokey,
        b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let err = match configure_tls(Some(cert), Some(nokey.to_str().unwrap())) {
        Err(error) => error,
        Ok(_) => panic!("a PEM with no private key must be an error"),
    };
    assert!(
        format!("{err:#}").contains("No private key found"),
        "{err:#}"
    );

    // Default path absent → Ok(None) (no IMAPS), not an error.
    if !std::path::Path::new("/opt/apexmail/certs/apexmail.crt").exists() {
        let none = configure_tls(None, None).expect("missing defaults are not fatal");
        assert!(none.is_none());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── paused-clock IDLE deadline ──────────────────────────────────────────────

#[tokio::test]
async fn idle_deadline_closes_with_bye() {
    // Duplex + paused clock (the repo's established pattern): every step is
    // under the test's control, so the only timer that matters is run_idle's
    // 29-minute deadline. No test-side `timeout` wrappers are used — with a
    // paused clock tokio auto-advances to the earliest timer, which must be
    // the server's deadline, not the test's own guard.
    tokio::time::pause();
    let mut h = Harness::new();
    let _ = select_two_messages(&mut h).await;
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut cont = Vec::new();
    h.io.read_until(b'\n', &mut cont).await.expect("read");
    assert!(cont.starts_with(b"+"), "IDLE continuation: {cont:?}");

    tokio::time::advance(Duration::from_secs(30 * 60)).await;

    // The deadline fires: a BYE is written and the serve task ends.
    let mut all = Vec::new();
    for _ in 0..5 {
        let mut line = Vec::new();
        let n = h.io.read_until(b'\n', &mut line).await.expect("read");
        if n == 0 {
            break;
        }
        all.extend_from_slice(&line);
        if line.starts_with(b"* BYE") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&all);
    assert!(
        text.contains("* BYE IDLE timeout, closing connection"),
        "IDLE deadline must produce a BYE: {text:?}"
    );
    h.server
        .await
        .expect("serve task ends after the IDLE deadline")
        .expect("serve loop returns Ok");
}

// ═══════════════════════════════════════════════════════════════════════════
// Coverage-driving adversarial batch 2: SEARCH date/criteria arms, FETCH item
// forms and failure isolation, COPY/MOVE/APPEND/STATUS/CLOSE error arms,
// NOOP transport tolerance, IDLE degraded modes, LSUB attributes.
// ═══════════════════════════════════════════════════════════════════════════

/// SEARCH TO/CC/BCC AND over envelope recipients, plus SINCE/BEFORE/ON date
/// filtering (valid and malformed dates).
#[tokio::test]
async fn search_recipient_and_date_criteria() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    // 2024-05-10 12:00 UTC and 2024-06-01 08:00 UTC.
    h.mock.add_message_with_recipients(
        "acct-1",
        "INBOX",
        (&["alice@dest.test"], &["carol@cc.test"], &["dave@bcc.test"]),
        mail_proto::MessageFlags::default(),
        1_715_342_400,
    );
    h.mock.add_message_with_recipients(
        "acct-1",
        "INBOX",
        (&["bob@dest.test"], &[], &[]),
        mail_proto::MessageFlags::default(),
        1_717_238_400,
    );
    h.mock
        .add_message("acct-", "INBOX", "s", "f@e.test", Default::default(), 0); // wrong account: must stay invisible

    let out = h.cmd("SEARCH TO \"alice\"").await;
    assert!(out.contains("* SEARCH 1\r\n"), "TO filter: {out:?}");

    let out = h.cmd("SEARCH CC \"carol\"").await;
    assert!(out.contains("* SEARCH 1\r\n"), "CC filter: {out:?}");

    let out = h.cmd("SEARCH BCC \"dave\"").await;
    assert!(out.contains("* SEARCH 1\r\n"), "BCC filter: {out:?}");

    let out = h.cmd("SEARCH TO \"nobody\"").await;
    assert!(
        out.contains("* SEARCH\r\n"),
        "no match => empty SEARCH: {out:?}"
    );

    let out = h.cmd("SEARCH SINCE 1-Jun-2024").await;
    assert!(out.contains("* SEARCH 2\r\n"), "SINCE: {out:?}");

    let out = h.cmd("SEARCH BEFORE 1-Jun-2024").await;
    assert!(out.contains("* SEARCH 1\r\n"), "BEFORE: {out:?}");

    let out = h.cmd("SEARCH ON 10-May-2024").await;
    assert!(
        out.contains("* SEARCH 1\r\n"),
        "ON day bounds are inclusive: {out:?}"
    );

    let out = h.cmd("SEARCH SINCE 10-May-2024").await;
    assert!(
        out.contains("* SEARCH 1 2"),
        "SINCE is inclusive of the day start: {out:?}"
    );

    let out = h.cmd("SEARCH BEFORE 99-Xyz-9999").await;
    assert!(
        out.contains("BAD") && out.contains("Invalid date"),
        "malformed date must be BAD: {out:?}"
    );

    // A criterion missing its date argument entirely is tolerated (i < len
    // guard) and matches everything, like most servers.
    let out = h.cmd("SEARCH SINCE").await;
    assert!(
        out.trim_end().ends_with("OK SEARCH completed"),
        "dangling SINCE: {out:?}"
    );

    let out = h.cmd("SEARCH TO").await;
    assert!(
        out.trim_end().ends_with("OK SEARCH completed"),
        "dangling TO: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn search_unrecent_and_header_arg_errors_are_bad() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    h.mock
        .add_message("acct-1", "INBOX", "s", "f@e.test", Default::default(), 0);

    let out = h.cmd("SEARCH UNRECENT").await;
    assert!(
        out.contains("BAD") && out.contains("UNRECENT is not a valid SEARCH criterion"),
        "{out:?}"
    );
    let out = h.cmd("SEARCH HEADER X-Only").await;
    assert!(
        out.contains("BAD") && out.contains("HEADER requires a field name and a value"),
        "{out:?}"
    );
    let out = h.cmd("SEARCH FROBNICATE").await;
    assert!(
        out.contains("BAD") && out.contains("Unsupported SEARCH criterion"),
        "{out:?}"
    );
    h.shutdown().await;
}

/// RFC822 / RFC822.HEADER / RFC822.TEXT item forms and the FAST macro.
#[tokio::test]
async fn fetch_rfc822_item_forms_and_fast_macro() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    let uid = h
        .mock
        .add_message("acct-1", "INBOX", "s", "f@e.test", Default::default(), 0);
    h.mock.set_body(
        "acct-1",
        "INBOX",
        uid,
        b"Subject: s\r\nFrom: f\r\n\r\nbody text\r\n",
    );

    let out = h.cmd("FETCH 1 FAST").await;
    assert!(out.contains("FLAGS"), "FAST expands to FLAGS: {out:?}");
    assert!(
        out.contains("INTERNALDATE"),
        "FAST expands to INTERNALDATE: {out:?}"
    );
    assert!(
        out.contains("RFC822.SIZE"),
        "FAST expands to RFC822.SIZE: {out:?}"
    );
    assert!(
        !out.contains("ENVELOPE"),
        "FAST must not carry ENVELOPE: {out:?}"
    );

    let out = h.cmd("FETCH 1 RFC822").await;
    assert!(
        out.contains("RFC822 {"),
        "RFC822 returns a literal: {out:?}"
    );
    assert!(out.contains("body text"), "{out:?}");

    let out = h.cmd("FETCH 1 RFC822.HEADER").await;
    assert!(out.contains("RFC822.HEADER {"), "{out:?}");
    assert!(out.contains("Subject: s"), "{out:?}");
    assert!(
        !out.contains("body text"),
        "header form must not carry the body: {out:?}"
    );

    let out = h.cmd("FETCH 1 RFC822.TEXT").await;
    assert!(out.contains("RFC822.TEXT {"), "{out:?}");
    assert!(out.contains("body text"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test]
async fn fetch_argument_error_arms_are_bad() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;

    // No sequence set at all.
    let out = h.cmd("FETCH").await;
    assert!(
        out.contains("BAD") && out.contains("FETCH requires a sequence set"),
        "{out:?}"
    );

    // Empty item list.
    let out = h.cmd("FETCH 1 ()").await;
    assert!(
        out.contains("BAD") && out.contains("at least one item"),
        "{out:?}"
    );

    // Malformed partial spec (no dot).
    let out = h.cmd("FETCH 1 BODY[]<5>").await;
    assert!(
        out.contains("BAD") && out.contains("expected <offset.octets>"),
        "{out:?}"
    );

    // Non-numeric partial offset.
    let out = h.cmd("FETCH 1 BODY[]<x.5>").await;
    assert!(
        out.contains("BAD") && out.contains("Invalid partial offset"),
        "{out:?}"
    );

    // Zero-octet partial.
    let out = h.cmd("FETCH 1 BODY[]<0.0>").await;
    assert!(
        out.contains("BAD") && out.contains("greater than zero"),
        "{out:?}"
    );

    // Unknown item.
    let out = h.cmd("FETCH 1 FROBNICATE").await;
    assert!(
        out.contains("BAD") && out.contains("Unknown FETCH item"),
        "{out:?}"
    );

    // HEADER.FIELDS with an empty list.
    let out = h.cmd("FETCH 1 BODY.PEEK[HEADER.FIELDS ()]").await;
    assert!(
        out.contains("BAD") && out.contains("at least one field name"),
        "{out:?}"
    );

    // HEADER.FIELDS without a parenthesized list.
    let out = h.cmd("FETCH 1 BODY.PEEK[HEADER.FIELDS DATE]").await;
    assert!(
        out.contains("BAD") && out.contains("requires a (field list)"),
        "{out:?}"
    );

    // Unsupported section specifier.
    let out = h.cmd("FETCH 1 BODY.PEEK[WHAT]").await;
    assert!(
        out.contains("BAD") && out.contains("Unsupported BODY section"),
        "{out:?}"
    );

    // Malformed sequence set.
    let out = h.cmd("FETCH x:y (FLAGS)").await;
    assert!(
        out.contains("BAD") && out.contains("invalid sequence"),
        "{out:?}"
    );
    h.shutdown().await;
}

/// A partial fetch whose offset lies beyond the payload answers an empty
/// literal (`{0}`), not the whole body and not an error.
#[tokio::test]
async fn fetch_partial_offset_past_end_yields_empty_literal() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    let uid = h
        .mock
        .add_message("acct-1", "INBOX", "s", "f@e.test", Default::default(), 0);
    h.mock.set_body("acct-1", "INBOX", uid, b"short");
    let out = h.cmd("FETCH 1 BODY.PEEK[]<9999.5>").await;
    assert!(
        out.contains("BODY[]<9999> {0}\r\n"),
        "offset past end: {out:?}"
    );
    assert!(out.trim_end().ends_with("OK FETCH completed"), "{out:?}");
    h.shutdown().await;
}

/// A \Seen flag store that fails (twice — the retry too) after the FETCH
/// response already advertised \Seen must NOT fail the FETCH: the response
/// was consumed; the mismatch is logged for reconciliation.
#[tokio::test]
async fn fetch_seen_store_failure_does_not_fail_the_command() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    let uid = h
        .mock
        .add_message("acct-1", "INBOX", "s", "f@e.test", Default::default(), 0);
    h.mock.set_body("acct-1", "INBOX", uid, b"body");
    h.mock.fail("set_flags");
    let out = h.cmd("FETCH 1 BODY[]").await;
    assert!(
        out.contains("BODY[] {4}"),
        "body must still be delivered: {out:?}"
    );
    assert!(
        out.trim_end().ends_with("OK FETCH completed"),
        "FETCH must stay OK: {out:?}"
    );
    h.shutdown().await;
}

/// COPY/MOVE answer OK with COPYUID even when the destination's status RPC
/// fails — the uidvalidity falls back to the source session's.
#[tokio::test]
async fn copy_and_move_destination_status_failure_falls_back_to_source_uidvalidity() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 77);
    h.mock.add_mailbox("acct-1", "Archive", 42);
    h.select("INBOX").await;
    h.mock
        .add_message("acct-1", "INBOX", "s", "f@e.test", Default::default(), 0);
    // Break get_mailbox_status AFTER the SELECT captured its view.
    h.mock.fail("get_mailbox_status");
    let out = h.cmd("COPY 1 Archive").await;
    assert!(
        out.contains("[COPYUID 77 1 1]"),
        "source uidvalidity fallback: {out:?}"
    );

    h.mock
        .add_message("acct-1", "INBOX", "s2", "f@e.test", Default::default(), 0);
    let out = h.cmd("MOVE 1 Archive").await;
    assert!(out.contains("[COPYUID 77 1 2]"), "MOVE fallback: {out:?}");
    assert!(
        out.contains("* 1 EXPUNGE"),
        "MOVE must expunge from the source view: {out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn copy_and_move_precondition_arms() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    // No mailbox selected: both are BAD (never touch the store).
    let out = h.cmd("COPY 1 INBOX").await;
    assert!(
        out.contains("BAD") && out.contains("No mailbox selected"),
        "{out:?}"
    );
    let out = h.cmd("MOVE 1 INBOX").await;
    assert!(
        out.contains("BAD") && out.contains("No mailbox selected"),
        "{out:?}"
    );

    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    // Malformed sequence set.
    let out = h.cmd("COPY bogus INBOX").await;
    assert!(out.contains("BAD"), "{out:?}");
    let out = h.cmd("MOVE bogus INBOX").await;
    assert!(out.contains("BAD"), "{out:?}");

    // An out-of-range set resolves empty: OK with nothing copied/moved.
    let out = h.cmd("COPY 88:88 INBOX").await;
    assert!(
        out.trim_end().ends_with("OK COPY completed"),
        "empty set COPY: {out:?}"
    );
    let out = h.cmd("MOVE 88:88 INBOX").await;
    assert!(
        out.trim_end().ends_with("OK MOVE completed"),
        "empty set MOVE: {out:?}"
    );
    h.shutdown().await;
}

/// EXPUNGE advertises the new EXISTS after removing messages.
#[tokio::test]
async fn expunge_emits_exists_after_removals() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    let deleted = || mail_proto::MessageFlags {
        deleted: true,
        ..Default::default()
    };
    h.mock
        .add_message("acct-1", "INBOX", "a", "f@e.test", deleted(), 0);
    h.mock
        .add_message("acct-1", "INBOX", "b", "f@e.test", deleted(), 0);
    h.mock
        .add_message("acct-1", "INBOX", "c", "f@e.test", Default::default(), 0);
    let out = h.cmd("EXPUNGE").await;
    assert_eq!(
        out.matches("* 1 EXPUNGE").count(),
        2,
        "renumbered descending expunges: {out:?}"
    );
    assert!(
        out.contains("* 1 EXISTS"),
        "EXISTS must follow the removals: {out:?}"
    );
    assert!(out.trim_end().ends_with("OK EXPUNGE completed"), "{out:?}");
    h.shutdown().await;
}

/// CLOSE reports NO (and keeps the session selected) when its silent expunge
/// fails — swallowing it would leave silently-unexpunged \Deleted mail.
#[tokio::test]
async fn close_reports_no_when_expunge_fails_and_stays_selected() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    h.mock
        .add_message("acct-1", "INBOX", "a", "f@e.test", Default::default(), 0);
    h.mock.fail("expunge");
    let out = h.cmd("CLOSE").await;
    assert!(
        out.contains("NO") && out.contains("expunge error"),
        "{out:?}"
    );
    // Still selected: a FETCH works without a fresh SELECT.
    let out = h.cmd("FETCH 1 (FLAGS)").await;
    assert!(
        out.trim_end().ends_with("OK FETCH completed"),
        "session must stay selected: {out:?}"
    );
    h.shutdown().await;
}

/// NOOP survives transport failures of both the status and the listing RPCs.
#[tokio::test]
async fn noop_tolerates_status_and_list_failures() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    h.mock
        .add_message("acct-1", "INBOX", "a", "f@e.test", Default::default(), 0);

    h.mock.fail("get_mailbox_status");
    let out = h.cmd("NOOP").await;
    assert!(
        out.trim_end().ends_with("OK NOOP completed"),
        "status failure must not fail NOOP: {out:?}"
    );
    h.shutdown().await;

    // A CHANGED view whose re-list fails must also not fail NOOP.
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    // External arrival bumps uidnext/exists so the change gate opens.
    h.mock
        .add_message("acct-1", "INBOX", "new", "f@e.test", Default::default(), 0);
    h.mock.fail("list_messages");
    let out = h.cmd("NOOP").await;
    assert!(
        out.trim_end().ends_with("OK NOOP completed"),
        "list failure must not fail NOOP: {out:?}"
    );
    h.shutdown().await;
}

/// STATUS: session-scoped RECENT for the selected mailbox, store RECENT for
/// others, transport-failure NO, and empty-name BAD.
#[tokio::test]
async fn status_recent_scoping_and_error_arms() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 5);
    h.mock.add_mailbox("acct-1", "Other", 9);
    // One unseen message observed at SELECT is this session's \Recent.
    h.mock
        .add_message("acct-1", "INBOX", "a", "f@e.test", Default::default(), 0);
    h.select("INBOX").await;

    let out = h.cmd("STATUS INBOX (RECENT)").await;
    assert!(
        out.contains("RECENT 1"),
        "selected mailbox reports session recency: {out:?}"
    );

    let out = h.cmd("STATUS Other (RECENT)").await;
    assert!(
        out.contains("RECENT 0"),
        "other mailboxes report the store counter: {out:?}"
    );

    h.mock.fail("get_mailbox_status");
    let out = h.cmd("STATUS INBOX (MESSAGES)").await;
    assert!(
        out.contains("NO") && out.contains("STATUS failed"),
        "{out:?}"
    );

    let out = h.cmd("STATUS \"\" (MESSAGES)").await;
    assert!(
        out.contains("BAD") && out.contains("Mailbox name required"),
        "{out:?}"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn append_argument_and_target_error_arms() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);

    let out = h.cmd("APPEND \"\" {5}\r\nhello").await;
    assert!(
        out.contains("BAD") && out.contains("APPEND requires a mailbox"),
        "{out:?}"
    );

    // A bare non-literal token cannot be the message payload.
    let out = h.cmd("APPEND INBOX not-a-literal").await;
    assert!(
        out.contains("BAD") && out.contains("requires a literal message"),
        "{out:?}"
    );

    // A quoted token in the date position is parsed as a date-time and
    // rejected when malformed.
    let out = h.cmd("APPEND INBOX \"not-a-date\" {5}\r\nhello").await;
    assert!(
        out.contains("BAD") && out.contains("Invalid date-time"),
        "{out:?}"
    );

    // Missing mailbox: NO [TRYCREATE] (covered elsewhere) — here break the
    // status RPC instead: any non-NotFound failure is a plain NO.
    h.mock.fail("get_mailbox_status");
    let out = h.cmd("APPEND INBOX {5}\r\nhello").await;
    assert!(
        out.contains("NO") && out.contains("APPEND failed"),
        "{out:?}"
    );
    h.shutdown().await;
}

/// APPEND into the currently selected mailbox updates the live view: the
/// response carries the new EXISTS/RECENT and the pushed UID joins the map.
#[tokio::test]
async fn append_into_selected_mailbox_updates_the_view() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    let out = h
        .cmd_with_literal("APPEND INBOX ", b"Subject: hi\r\n\r\nbody\r\n", "")
        .await;
    assert!(
        out.contains("* 1 EXISTS"),
        "EXISTS must be advertised: {out:?}"
    );
    assert!(
        out.trim_end()
            .ends_with("OK [APPENDUID 1 1] APPEND completed"),
        "{out:?}"
    );
    // The view knows the new message.
    let out = h.cmd("FETCH 1 (UID)").await;
    assert!(out.contains("UID 1"), "{out:?}");
    h.shutdown().await;
}

/// AUTHENTICATE PLAIN exchange edge arms: cancel with "*", invalid base64,
/// malformed SASL payload, and a non-PLAIN mechanism.
#[tokio::test]
async fn authenticate_edge_arms_over_tls() {
    let mut h = Harness::with_session("127.0.0.1", true, false, true);
    h.read_greeting().await;

    let out = h.cmd("AUTHENTICATE FROB").await;
    assert!(
        out.contains("NO") && out.contains("Unsupported AUTH mechanism"),
        "{out:?}"
    );

    // Cancel the continuation exchange.
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} AUTHENTICATE PLAIN")).await;
    let mut cont = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut cont)).await;
    assert!(
        cont.starts_with(b"+"),
        "continuation: {:?}",
        String::from_utf8_lossy(&cont)
    );
    h.send_line("*").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("BAD") && out.contains("cancelled"), "{out:?}");

    // Invalid base64 on the continuation line.
    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} AUTHENTICATE PLAIN")).await;
    let mut cont = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut cont)).await;
    h.send_line("!!!not-base64!!!").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(
        out.contains("BAD") && out.contains("Invalid base64"),
        "{out:?}"
    );

    // Base64 that does not decode to authcid\0passwd.
    let bad = base64::engine::general_purpose::STANDARD.encode(b"only-authcid");
    let out = h.cmd(&format!("AUTHENTICATE PLAIN {bad}")).await;
    assert!(
        out.contains("BAD") && out.contains("Invalid AUTHENTICATE payload"),
        "{out:?}"
    );

    // Empty initial response.
    let out = h.cmd("AUTHENTICATE PLAIN \"\"").await;
    assert!(
        out.contains("BAD") && out.contains("cancelled"),
        "empty IR cancels: {out:?}"
    );
    h.shutdown().await;
}

/// IDLE with a broken event subscription (mailstore down) must still work as
/// a poll: no events, DONE terminates, junk lines get BAD, blank lines are
/// ignored.
#[tokio::test]
async fn idle_with_failed_subscription_ignores_events_and_ends_on_done() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;
    h.mock.fail("subscribe_mailbox");

    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut plus = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut plus)).await;
    assert!(
        plus.starts_with(b"+"),
        "idling continuation: {:?}",
        String::from_utf8_lossy(&plus)
    );

    // A blank line is ignored (continue), junk gets BAD but IDLE continues.
    h.send_line("").await;
    h.send_line("x1 SELECT INBOX").await;
    let mut bad = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut bad)).await;
    let bad_text = String::from_utf8_lossy(&bad).into_owned();
    assert!(
        bad_text.starts_with("x1 BAD") && bad_text.contains("not allowed during IDLE"),
        "{bad_text:?}"
    );

    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("OK IDLE terminated"), "{out:?}");
    h.shutdown().await;
}

/// IDLE ending on LOGOUT: BYE + tagged OK, session state Logout.
#[tokio::test]
async fn idle_logout_during_idle_ends_the_session() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 1);
    h.select("INBOX").await;

    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut plus = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut plus)).await;
    assert!(
        plus.starts_with(b"+"),
        "{:?}",
        String::from_utf8_lossy(&plus)
    );
    h.send_line("z9 LOGOUT").await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    assert!(text.contains("* BYE"), "BYE before the tagged OK: {text:?}");
    let mut ok = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut ok)).await;
    assert!(
        ok.starts_with(b"z9 OK"),
        "tagged OK under the CLIENT's tag: {:?}",
        String::from_utf8_lossy(&ok)
    );
    // The server task ends.
    let _ = tokio::time::timeout(Duration::from_secs(5), h.server).await;
}

/// LSUB reports attributes and the real delimiter for a subscribed mailbox
/// that still exists, and no attributes for a vanished one.
#[tokio::test]
async fn lsub_reports_attributes_for_existing_subscriptions() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "Plain", 1);
    h.mock.set_mailbox_row(
        "acct-1",
        mail_proto::Mailbox {
            name: "Plain".to_string(),
            delimiter: "/".to_string(),
            attributes: vec!["\\Archive".to_string()],
            uidvalidity: 1,
            ..Default::default()
        },
    );
    h.cmd("SUBSCRIBE Plain").await;
    // A subscription to a mailbox the store no longer knows about.
    h.cmd("SUBSCRIBE Ghost").await;
    let out = h.cmd("LSUB \"\" \"*\"").await;
    assert!(
        out.contains("* LSUB (\\Archive) \"/\" \"Plain\""),
        "existing subscription carries attrs+delimiter: {out:?}"
    );
    assert!(
        out.contains("* LSUB () \"/\" \"Ghost\""),
        "vanished subscription lists with no attributes: {out:?}"
    );
    h.shutdown().await;
}

/// LIST: a mailbox whose store delimiter is empty renders as NIL.
#[tokio::test]
async fn list_renders_an_empty_delimiter_as_nil() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "Weird", 1);
    h.mock.set_mailbox_row(
        "acct-1",
        mail_proto::Mailbox {
            name: "Weird".to_string(),
            delimiter: String::new(),
            ..Default::default()
        },
    );
    let out = h.cmd("LIST \"\" \"*\"").await;
    assert!(
        out.contains("* LIST () NIL \"Weird\""),
        "empty delimiter must be NIL: {out:?}"
    );
    h.shutdown().await;
}

/// IDLE event stream: a removal and an arrival must surface as EXPUNGE (in
/// descending order), EXISTS, RECENT and UIDNEXT — and DONE still terminates.
#[tokio::test]
async fn idle_events_surface_expunge_exists_recent_uidnext() {
    let mut h = Harness::new();
    h.login("u@e.test", "pw").await;
    h.mock.add_mailbox("acct-1", "INBOX", 4);
    h.select("INBOX").await;
    let deleted = || mail_proto::MessageFlags {
        deleted: true,
        ..Default::default()
    };
    h.mock
        .add_message("acct-1", "INBOX", "a", "f@e.test", deleted(), 0);
    h.mock
        .add_message("acct-1", "INBOX", "b", "f@e.test", Default::default(), 0);
    // Sync the session view to the two messages.
    h.noop().await;

    let tag = h.fresh_tag();
    h.send_line(&format!("{tag} IDLE")).await;
    let mut plus = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), h.io.read_until(b'\n', &mut plus)).await;
    assert!(
        plus.starts_with(b"+"),
        "{:?}",
        String::from_utf8_lossy(&plus)
    );

    // Remove uid 1 through the real service, then announce it.
    let _ = MailstoreService::expunge(
        &h.mock,
        tonic::Request::new(mail_proto::ExpungeRequest {
            account_id: "acct-1".into(),
            mailbox: "INBOX".into(),
            uids: vec![1],
        }),
    )
    .await
    .expect("mock expunge");
    h.mock
        .events_sender("acct-1", "INBOX")
        .send(MailboxEvent {
            event: Some(mail_proto::mailbox_event::Event::MessageRemoved(
                mail_proto::MessageRemoved { uid: 1 },
            )),
        })
        .expect("send removal event");

    // Add two fresh unseen messages and announce the arrival.
    h.mock
        .add_message("acct-1", "INBOX", "c", "f@e.test", Default::default(), 0);
    h.mock
        .add_message("acct-1", "INBOX", "d", "f@e.test", Default::default(), 0);
    h.mock
        .events_sender("acct-1", "INBOX")
        .send(MailboxEvent {
            event: Some(mail_proto::mailbox_event::Event::MessageAdded(
                mail_proto::MessageAdded {
                    message: Some(mail_proto::MessageMeta {
                        uid: 3,
                        account_id: "acct-1".into(),
                        mailbox: "INBOX".into(),
                        ..Default::default()
                    }),
                },
            )),
        })
        .expect("send arrival event");

    let mut seen = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let mut line = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(2), h.io.read_until(b'\n', &mut line))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        seen.push_str(&String::from_utf8_lossy(&line));
        if seen.contains("[UIDNEXT") {
            break;
        }
    }
    assert!(seen.contains("* 1 EXPUNGE"), "removal expunged: {seen:?}");
    assert!(seen.contains("* 3 EXISTS"), "arrivals advertised: {seen:?}");
    assert!(
        seen.contains("* 3 RECENT"),
        "unseen arrivals are recent: {seen:?}"
    );
    assert!(
        seen.contains("* OK [UIDNEXT 5]"),
        "uidnext bumped: {seen:?}"
    );

    h.send_line("DONE").await;
    let out = h.read_until_tagged(&tag).await;
    assert!(out.contains("OK IDLE terminated"), "{out:?}");
    h.shutdown().await;
}
