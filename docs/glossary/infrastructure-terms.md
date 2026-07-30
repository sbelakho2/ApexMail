# ApexMail Infrastructure Terminology

Authoritative definitions for every infrastructure term used across
marketing, pricing, sales, documentation, and legal pages.

---

## Shared Cloud

A multi-tenant deployment model where multiple ApexMail customers share the
same application infrastructure, compute resources, and network. Each
customer's data is logically isolated at the application layer but shares
physical and virtual infrastructure with other customers. This is the
standard deployment for Free through Enterprise (Shared) plans.

**Key distinction**: Shared cloud does not mean shared data. Application-
level multi-tenancy enforces strict data isolation between tenants.

---

## Dedicated IP

A publicly routable IP address assigned exclusively to one ApexMail
customer for outbound email delivery. The customer builds and manages their
own sending reputation on this IP.

**Key distinction**: A dedicated IP is NOT equivalent to dedicated
infrastructure or single tenancy. It only isolates the sending IP address;
all other infrastructure remains shared.

---

## Dedicated Infrastructure

A deployment where compute, networking, and storage resources are
provisioned exclusively for one customer. This includes dedicated
application servers, optional dedicated database instances, and a private
network configuration.

**Key distinction**: Dedicated infrastructure provides resource isolation
but may still run within ApexMail-managed cloud accounts. See "Private
Cloud" and "BYOC" for customer-controlled alternatives.

---

## Single Tenant

A synonym for Dedicated Infrastructure within ApexMail product
documentation. Refers to the Dedicated Tenant deployment product where one
customer occupies the entire deployment with no other customers on the
same application infrastructure.

**Key distinction**: Single tenant means application-level isolation.
"Private Cloud" or "BYOC" additionally provides cloud-account-level
isolation.

---

## Private Cloud

An ApexMail deployment option where the customer receives dedicated
infrastructure within an ApexMail-managed cloud account, with private
networking, customer-specific maintenance windows, and enhanced operational
controls. This is the "Dedicated Tenant" deployment product.

**Key distinction**: Private Cloud copy must use this approved definition
and not imply the customer controls the cloud account itself (see BYOC for
that). "Private Cloud" ≠ "customer cloud account."

---

## Customer Cloud

An ApexMail deployment option where the software is deployed into the
customer's own cloud account (AWS, GCP, Azure). The customer retains full
control over the cloud account, including networking, IAM, encryption keys,
and compliance scope. This is the "BYOC" (Bring Your Own Cloud) deployment
product.

**Key distinction**: Customer Cloud means the customer owns and controls the
cloud account. ApexMail provides software licensing, deployment automation,
upgrades, and operational support but does not control the cloud account.

---

## Customer-Controlled Infrastructure

Infrastructure where the customer has root-level or equivalent administrative
control. This applies to BYOC deployments where the customer manages cloud
accounts, networking, IAM, and encryption key management.

**Key distinction**: Not all dedicated infrastructure is customer-controlled.
Dedicated Tenant deployments are ApexMail-managed (shared cloud account
responsibility). BYOC deployments are customer-controlled.

---

## On-Premises

A deployment where ApexMail software runs on hardware physically located
within the customer's own data center, not in a public cloud.

**Status**: Not currently offered as a standard product. Available only
through custom engineering engagement.

**Key distinction**: On-premises is not synonymous with Private Cloud or BYOC.

---

## Data Residency

The commitment that customer data (messages, metadata, recipient addresses,
attachments) is stored and processed within a defined geographic region.
ApexMail's standard deployment stores all data within the European Economic
Area (EEA).

**Key distinction**: Data residency is about WHERE data is stored. It is NOT
the same as data sovereignty (which concerns legal jurisdiction) or data
localization (which is a legal requirement to store data in a specific
country).

---

## Data Localization

A legal or regulatory requirement mandating that certain data categories
must be stored and processed within a specific country's borders.

**Key distinction**: Data localization is a legal obligation, not an
architectural choice. ApexMail's standard EEA data residency may satisfy
EU-member-state localization requirements but does not guarantee compliance
with non-EU localization laws unless confirmed for a specific jurisdiction.

---

## Data Sovereignty

The principle that data is subject to the laws and governance of the country
where it is physically stored. If data resides in Estonia, it is governed by
Estonian and EU law.

**Key distinction**: Data sovereignty is a legal concept, not an
infrastructure feature. ApexMail's EEA data residency provides EU data
sovereignty. "Data residency" must not be presented as "data sovereignty"
unless the architecture demonstrably supports that claim for the relevant
jurisdiction.

---

## Regional Deployment

A deployment of ApexMail where the entire application stack (compute, data,
networking) runs within a single geographic cloud region. Standard
deployments are within a defined EEA region.

**Key distinction**: Regional deployment is a single-region deployment.
It does not imply multi-region or cross-region capabilities.

---

## Multi-Region

A deployment architecture where production infrastructure is distributed
across two or more geographic regions, with production traffic actively
served from multiple regions and the ability to fail over between them.

**Status**: Not a currently available product feature.

**Key distinction**: Multi-region must NOT be claimed unless production
traffic can actually fail between regions seamlessly. EEA data residency
with availability-zone redundancy is NOT multi-region.

---

## High Availability

An architectural property where the system remains operational and
accessible despite individual component failures. Achieved through
redundancy, automated failover, health checking, and load distribution.

**ApexMail implementation**: Standard deployment includes multiple
availability zones, load-balanced API endpoints, database replication, and
automatic instance replacement.

**Key distinction**: High availability reduces downtime from component
failure; it is NOT a guarantee of zero downtime.

---

## Redundancy

Duplication of critical system components so that if one fails, another can
take over. Includes compute instances, database replicas, network paths, and
storage.

**Key distinction**: Redundancy enables high availability and failover but
is not the same as either. Redundancy is the configuration; high availability
and failover are the behaviors enabled by redundancy.

---

## Failover

The automatic or manual process of switching from a failed component to a
redundant standby. Includes database failover (primary → replica promotion),
instance failover, and network path failover.

**Key distinction**: Failover is the mechanism. It requires redundancy to
exist and is part of a high-availability strategy. It is distinct from
disaster recovery, which operates at a larger scale.

---

## Disaster Recovery

The process and procedures for restoring service after a catastrophic event
that destroys or renders inaccessible the primary deployment. Includes data
restoration from backups, infrastructure re-provisioning, and DNS cutover.

**Key distinction**: Disaster recovery is a recovery process, not a real-time
failover mechanism. Recovery Time Objective (RTO) and Recovery Point
Objective (RPO) define the recovery parameters.

---

## Backup

A point-in-time copy of data (databases, message stores, configuration)
stored separately from the primary data location, used for recovery purposes.

**ApexMail implementation**: Automated daily backups with configurable
retention. Backups are stored in a separate storage account from primary
data stores.

**Key distinction**: Backups are a component of disaster recovery, not
disaster recovery itself. Backups must be tested (restoration drills).

---

## Recovery-Point Objective (RPO)

The maximum acceptable amount of data loss measured in time. If RPO is
1 hour, backups must be taken at least every hour, and a disaster could
result in losing up to 1 hour of data.

**ApexMail default**: 1 hour for message data; 24 hours for configuration.

**Key distinction**: RPO is about data loss tolerance, not service recovery
time (that is RTO).

---

## Recovery-Time Objective (RTO)

The maximum acceptable duration of service unavailability after a disaster.
If RTO is 4 hours, service must be restored and operational within 4 hours
of the disaster event.

**ApexMail default**: 4 hours for standard deployments; 1 hour for
Dedicated Tenant with enhanced SLA.

**Key distinction**: RTO is about time to recover, not how much data is lost
(that is RPO).

---

## Completion Requirements Checklist

- [x] Private Cloud copy uses one approved definition.
- [x] Dedicated IP is not presented as equivalent to single tenancy.
- [x] Data residency is not presented as data sovereignty unless the
      architecture supports that claim.
- [x] Multi-Region is not claimed unless production traffic can actually
      fail between regions.
