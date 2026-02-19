import * as React from 'react';

export interface ApexIconProps extends React.SVGProps<SVGSVGElement> {
  size?: number;
  strokeWidth?: number;
}

export type ApexIconComponent = React.FC<ApexIconProps>;

type Glyph =
  | 'arrow-right'
  | 'arrow-left'
  | 'arrow-up-right'
  | 'arrow-down-right'
  | 'arrow-left-right'
  | 'arrow-up-down'
  | 'chevron-right'
  | 'chevron-left'
  | 'chevron-up'
  | 'chevron-down'
  | 'check'
  | 'plus'
  | 'minus'
  | 'x'
  | 'dot'
  | 'badge'
  | 'lock'
  | 'key'
  | 'mail'
  | 'user'
  | 'users'
  | 'bot'
  | 'bug'
  | 'search'
  | 'alert'
  | 'info'
  | 'calendar'
  | 'clock'
  | 'settings'
  | 'bar-chart'
  | 'spark'
  | 'mouse-pointer'
  | 'eye'
  | 'quote'
  | 'code'
  | 'terminal'
  | 'cloud'
  | 'server'
  | 'network'
  | 'database'
  | 'globe'
  | 'fingerprint'
  | 'phone'
  | 'smartphone'
  | 'message'
  | 'message-square'
  | 'book'
  | 'building'
  | 'ticket'
  | 'tag'
  | 'flag'
  | 'flame'
  | 'target'
  | 'activity'
  | 'history'
  | 'layers'
  | 'git-branch'
  | 'github'
  | 'twitter'
  | 'linkedin'
  | 'scale'
  | 'file'
  | 'download'
  | 'upload'
  | 'save'
  | 'copy'
  | 'trash'
  | 'pencil'
  | 'play'
  | 'pause'
  | 'skip-back'
  | 'skip-forward'
  | 'list-filter'
  | 'inbox'
  | 'bell'
  | 'moon'
  | 'sun'
  | 'monitor'
  | 'home'
  | 'help'
  | 'credit-card'
  | 'euro'
  | 'menu'
  | 'logout'
  | 'more'
  | 'spinner'
  | 'lightbulb'
  | 'sparkles'
  | 'brain'
  | 'gauge'
  | 'webhook'
  | 'hash'
  | 'link'
  | 'trophy'
  | 'calculator'
  | 'dollar'
  | 'trend-up'
  | 'trend-down'
  | 'clipboard'
  | 'phone-line'
  | 'headphones'
  | 'folder'
  | 'shield';

const glyphs: Record<Glyph, React.ReactNode> = {
  'arrow-right': <path d="M5 12h12m-4-4 4 4-4 4" />,
  'arrow-left': <path d="M19 12H7m4-4-4 4 4 4" />,
  'arrow-up-right': <path d="M7 17 17 7m-6 0h6v6" />,
  'arrow-down-right': <path d="M7 7l10 10m0-6v6h-6" />,
  'arrow-left-right': <path d="M7 8 3 12l4 4m10-8 4 4-4 4M4 12h16" />,
  'arrow-up-down': <path d="M12 4v16m-4-4 4 4 4-4m-4-12-4 4m4-4 4 4" />,
  'chevron-right': <path d="m9 6 6 6-6 6" />,
  'chevron-left': <path d="m15 6-6 6 6 6" />,
  'chevron-up': <path d="m6 15 6-6 6 6" />,
  'chevron-down': <path d="m6 9 6 6 6-6" />,
  check: <path d="M6 12l4 4 8-8" />,
  plus: <path d="M12 5v14M5 12h14" />,
  minus: <path d="M5 12h14" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  dot: <circle cx="12" cy="12" r="2" />,
  badge: <path d="M12 3l7 3v6c0 4.2-3.2 6.6-7 9-3.8-2.4-7-4.8-7-9V6l7-3z" />,
  lock: <path d="M7 11h10v8H7zM9 11V8a3 3 0 0 1 6 0v3" />,
  key: <path d="M14 10a3 3 0 1 1-6 0 3 3 0 0 1 6 0zm0 0h6v4h-4" />,
  mail: <path d="M4 6h16v12H4zM4 7l8 6 8-6" />,
  user: <path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4zm-6 7c1.5-3 10.5-3 12 0" />,
  users: <path d="M8 11a3 3 0 1 0-3-3 3 3 0 0 0 3 3zm8 0a3 3 0 1 0-3-3 3 3 0 0 0 3 3M4 19c1.2-2.4 7-2.8 8-1m2 1c1-1.8 5.6-2.2 6-1" />,
  bot: <path d="M7 7h10v10H7zM9 11h.01M15 11h.01M10 15h4" />,
  bug: (
    <>
      <path d="M9 9a3 3 0 0 1 6 0v6a3 3 0 0 1-6 0z" />
      <path d="M12 5v2" />
      <path d="M8 7 6 5" />
      <path d="M16 7l2-2" />
      <path d="M6 12h3" />
      <path d="M15 12h3" />
      <path d="M6 16h3" />
      <path d="M15 16h3" />
    </>
  ),
  search: <path d="M11 5a6 6 0 1 0 0 12 6 6 0 0 0 0-12zm8 14-4-4" />,
  alert: <path d="M12 5 20 19H4zM12 10v4m0 3h.01" />,
  info: <path d="M12 8h.01M11 11h2v6" />,
  calendar: <path d="M6 7h12v12H6zM8 4v3m8-3v3M6 10h12" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="7" />
      <path d="M12 8v4l3 2" />
    </>
  ),
  settings: <path d="M4 7h9m3 0h4M8 7v2m4 8H4m14 0h2m-6 0v2" />,
  'bar-chart': <path d="M6 18V9m6 9V6m6 12v-4" />,
  spark: <path d="M12 4l1.5 3.5L17 9l-3.5 1.5L12 14l-1.5-3.5L7 9l3.5-1.5L12 4z" />,
  'mouse-pointer': <path d="M5 4l7 16 2-6 6-2L5 4z" />,
  eye: <path d="M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6zm9 3a3 3 0 1 0-3-3 3 3 0 0 0 3 3z" />,
  quote: <path d="M7 9h4v6H5V9h2zm10 0h4v6h-6V9h2" />,
  code: <path d="M9 8 5 12l4 4m6-8 4 4-4 4" />,
  terminal: <path d="M4 6h16v12H4zM7 10l3 2-3 2m6 2h4" />,
  cloud: <path d="M7 18h9a4 4 0 0 0 .5-8 5 5 0 0 0-9.7 1A3.5 3.5 0 0 0 7 18z" />,
  server: <path d="M5 6h14v4H5zM5 14h14v4H5z" />,
  network: (
    <>
      <circle cx="12" cy="6" r="2" />
      <circle cx="6" cy="18" r="2" />
      <circle cx="18" cy="18" r="2" />
      <path d="M12 8v4m0 0-6 4m6-4 6 4" />
    </>
  ),
  database: <path d="M5 7c0-2 14-2 14 0v10c0 2-14 2-14 0zM5 11c0 2 14 2 14 0" />,
  globe: <path d="M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 0c2.5 2.2 2.5 9.8 0 12m0-12c-2.5 2.2-2.5 9.8 0 12M4 12h16" />,
  fingerprint: <path d="M8 7a4 4 0 0 1 8 0m-8 4a4 4 0 0 0 8 0m-8 4a6 6 0 0 0 8 0" />,
  phone: <path d="M7 4h10v16H7zM11 16h2" />,
  smartphone: (
    <>
      <rect x="7" y="3" width="10" height="18" rx="2" />
      <path d="M11 17h2" />
    </>
  ),
  message: <path d="M5 6h14v9H8l-3 3V6z" />,
  'message-square': <path d="M4 6h16v10H8l-4 4V6z" />,
  book: <path d="M5 6h7v12H5zM12 6h7v12h-7M8 8h2M15 8h2" />,
  building: <path d="M5 5h14v14H5zM9 9h2m4 0h2M9 13h2m4 0h2" />,
  ticket: <path d="M5 7h14v3a2 2 0 0 1 0 4v3H5v-3a2 2 0 0 0 0-4V7z" />,
  tag: <path d="M4 10l6-6h6l4 4v6l-6 6-10-10z" />,
  flag: <path d="M5 4v16m0-14h10l-2 3 2 3H5" />,
  flame: <path d="M12 4c3 4 2 5.5 0 7-2 1.5-2 4 0 6-4 0-6-3-6-6 0-3 2-5 6-7z" />,
  target: <path d="M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8" />,
  activity: <path d="M4 12h4l2-4 3 8 3-6h4" />,
  history: <path d="M5 12a7 7 0 1 0 3-5.7M5 12V7h5m2 1v5l3 2" />,
  layers: <path d="M12 5 4 9l8 4 8-4-8-4zm-8 8 8 4 8-4" />,
  'git-branch': <path d="M6 4v10a3 3 0 0 0 6 0V10a3 3 0 0 1 6 0v6" />,
  github: (
    <>
      <circle cx="12" cy="12" r="6" />
      <circle cx="9" cy="11" r="1" />
      <circle cx="15" cy="11" r="1" />
      <path d="M10 15c1.3 1 2.7 1 4 0" />
    </>
  ),
  twitter: (
    <>
      <circle cx="6.5" cy="17.5" r="1" />
      <path d="M6.5 17.5a4 4 0 0 0 4-4" />
      <path d="M6.5 17.5a7 7 0 0 0 7-7" />
    </>
  ),
  linkedin: (
    <>
      <circle cx="7.5" cy="6.5" r="1.5" />
      <rect x="6" y="9" width="3" height="9" />
      <rect x="11" y="12" width="7" height="6" />
    </>
  ),
  scale: <path d="M12 5v14M5 8h14M7 8l-3 5h6l-3-5zm10 0-3 5h6l-3-5" />,
  file: <path d="M7 4h7l3 3v13H7zM14 4v3h3" />,
  download: <path d="M12 5v10m0 0-4-4m4 4 4-4M5 19h14" />,
  upload: <path d="M12 19V9m0 0-4 4m4-4 4 4M5 5h14" />,
  save: <path d="M5 4h12l3 3v13H5zM8 4v6h8V6" />,
  copy: <path d="M9 9h10v10H9zM5 5h10v10H5z" />,
  trash: <path d="M6 7h12m-9 0 1 12h6l1-12M9 7V5h6v2" />,
  pencil: <path d="M5 19h4l9-9-4-4-9 9v4zm9-12 4 4" />,
  play: <path d="M7 5l11 7-11 7z" />,
  pause: <path d="M8 6v12m8-12v12" />,
  'skip-back': <path d="M7 5v14m0-7 10-7v14L7 12z" />,
  'skip-forward': <path d="M17 5v14m0-7-10-7v14l10-7z" />,
  'list-filter': <path d="M4 7h16M7 12h10M10 17h4" />,
  inbox: <path d="M4 6h16v10h-5l-3 3-3-3H4z" />,
  bell: <path d="M12 5a4 4 0 0 1 4 4v4l2 3H6l2-3V9a4 4 0 0 1 4-4zm0 14a2 2 0 0 0 2-2h-4a2 2 0 0 0 2 2z" />,
  moon: <path d="M15 4a7 7 0 1 0 5 11A7 7 0 0 1 15 4z" />,
  sun: <path d="M12 4v2m0 12v2m8-8h-2M6 12H4m12.5-5.5-1.5 1.5m-7 7-1.5 1.5m0-10 1.5 1.5m7 7 1.5 1.5M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z" />,
  monitor: <path d="M4 6h16v10H4zM10 20h4M8 16v4m8-4v4" />,
  home: <path d="M4 12l8-7 8 7v7H4zM9 19v-6h6v6" />,
  help: <path d="M12 18h.01M9.5 9a3 3 0 1 1 5 2.2c-.8.5-1.5 1.1-1.5 2.3" />,
  'credit-card': <path d="M4 7h16v10H4zM4 10h16M7 15h4" />,
  euro: <path d="M16 7a4 4 0 0 0-4-2 4 4 0 0 0 0 8 4 4 0 0 0 4-2M6 10h6M6 14h6" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  logout: (
    <>
      <path d="M10 5H6v14h4" />
      <path d="M14 16l4-4-4-4" />
      <path d="M8 12h10" />
    </>
  ),
  more: <path d="M6 12h.01M12 12h.01M18 12h.01" />,
  spinner: <path d="M12 4a8 8 0 1 1-5.6 2.4" />,
  lightbulb: <path d="M12 4a5 5 0 0 0-3 9v3h6v-3a5 5 0 0 0-3-9zm-2 14h4" />,
  sparkles: <path d="M8 4l1.5 3L12 8l-2.5 1L8 12l-1.5-3L4 8l2.5-1L8 4zm8 6 1 2 2 1-2 1-1 2-1-2-2-1 2-1 1-2z" />,
  brain: <path d="M9 6a3 3 0 0 1 6 0 3 3 0 0 1 3 3 3 3 0 0 1-2 3 3 3 0 0 1-3 4H10a3 3 0 0 1-3-3 3 3 0 0 1-2-3 3 3 0 0 1 4-4" />,
  gauge: <path d="M5 16a7 7 0 0 1 14 0M12 10l3 4" />,
  webhook: <path d="M7 7a3 3 0 1 0 0 6m10 4a3 3 0 1 1 0-6M7 13h6M11 7h6" />,
  hash: <path d="M7 5 5 19m6-14-2 14m-3-5h12m-11-4h12" />,
  link: <path d="M9 8h3a3 3 0 0 1 0 6H9m6-6h-3a3 3 0 0 0 0 6h3" />,
  trophy: <path d="M6 6h12v3a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V6zm6 7v5m-3 0h6" />,
  calculator: <path d="M6 4h12v16H6zM8 8h8M8 12h3m2 0h3M8 16h3m2 0h3" />,
  dollar: <path d="M12 4v16m3-12H9a3 3 0 1 0 0 6h6a3 3 0 1 1 0 6H9" />,
  'trend-up': <path d="M5 15l5-5 4 4 5-6" />,
  'trend-down': <path d="M5 9l5 5 4-4 5 6" />,
  clipboard: <path d="M8 5h8v14H8zM10 3h4v2h-4z" />,
  'phone-line': <path d="M7 5h10v14H7zM11 16h2" />,
  headphones: <path d="M4 13a8 8 0 0 1 16 0v5h-3v-5h-2v5H9v-5H7v5H4z" />,
  folder: <path d="M4 7h6l2 2h8v8H4z" />,
  shield: <path d="M12 3l7 3v6c0 4.2-3.2 6.6-7 9-3.8-2.4-7-4.8-7-9V6l7-3z" />,
};

const createIcon = (glyph: Glyph): ApexIconComponent => {
  const Icon: ApexIconComponent = ({
    size = 20,
    strokeWidth = 1.75,
    className,
    ...props
  }) => (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
      {...props}
    >
      {glyphs[glyph]}
    </svg>
  );

  return Icon;
};

export const ArrowRight = createIcon('arrow-right');
export const ArrowLeft = createIcon('arrow-left');
export const ArrowUpRight = createIcon('arrow-up-right');
export const ArrowDownRight = createIcon('arrow-down-right');
export const ArrowLeftRight = createIcon('arrow-left-right');
export const ArrowUpDown = createIcon('arrow-up-down');
export const ChevronRight = createIcon('chevron-right');
export const ChevronLeft = createIcon('chevron-left');
export const ChevronUp = createIcon('chevron-up');
export const ChevronDown = createIcon('chevron-down');
export const Check = createIcon('check');
export const CheckCircle = createIcon('check');
export const CheckCircle2 = createIcon('check');
export const Plus = createIcon('plus');
export const Minus = createIcon('minus');
export const X = createIcon('x');
export const Circle = createIcon('dot');
export const Shield = createIcon('badge');
export const ShieldCheck = createIcon('badge');
export const Lock = createIcon('lock');
export const Key = createIcon('key');
export const Mail = createIcon('mail');
export const MessageCircle = createIcon('message');
export const MessageSquare = createIcon('message-square');
export const Send = createIcon('arrow-right');
export const User = createIcon('user');
export const UserPlus = createIcon('users');
export const Users = createIcon('users');
export const Bot = createIcon('bot');
export const Bug = createIcon('bug');
export const Search = createIcon('search');
export const Filter = createIcon('list-filter');
export const AlertTriangle = createIcon('alert');
export const AlertCircle = createIcon('alert');
export const Info = createIcon('info');
export const XCircle = createIcon('x');
export const Calendar = createIcon('calendar');
export const Clock = createIcon('clock');
export const Settings = createIcon('settings');
export const BarChart3 = createIcon('bar-chart');
export const Sparkles = createIcon('sparkles');
export const Zap = createIcon('spark');
export const MousePointer = createIcon('mouse-pointer');
export const Eye = createIcon('eye');
export const Quote = createIcon('quote');
export const Code = createIcon('code');
export const Code2 = createIcon('code');
export const Terminal = createIcon('terminal');
export const Cloud = createIcon('cloud');
export const Server = createIcon('server');
export const Network = createIcon('network');
export const Database = createIcon('database');
export const Globe = createIcon('globe');
export const Fingerprint = createIcon('fingerprint');
export const Phone = createIcon('phone');
export const Smartphone = createIcon('smartphone');
export const Headphones = createIcon('headphones');
export const Book = createIcon('book');
export const BookOpen = createIcon('book');
export const Building = createIcon('building');
export const Building2 = createIcon('building');
export const Ticket = createIcon('ticket');
export const Tag = createIcon('tag');
export const Flag = createIcon('flag');
export const Flame = createIcon('flame');
export const Target = createIcon('target');
export const Activity = createIcon('activity');
export const History = createIcon('history');
export const Layers = createIcon('layers');
export const GitBranch = createIcon('git-branch');
export const Github = createIcon('github');
export const Twitter = createIcon('twitter');
export const Linkedin = createIcon('linkedin');
export const Scale = createIcon('scale');
export const FileText = createIcon('file');
export const FileCheck = createIcon('file');
export const FileCode = createIcon('file');
export const ScrollText = createIcon('file');
export const Download = createIcon('download');
export const Upload = createIcon('upload');
export const Save = createIcon('save');
export const Copy = createIcon('copy');
export const Trash2 = createIcon('trash');
export const Pencil = createIcon('pencil');
export const Play = createIcon('play');
export const Pause = createIcon('pause');
export const SkipBack = createIcon('skip-back');
export const SkipForward = createIcon('skip-forward');
export const ListFilter = createIcon('list-filter');
export const Inbox = createIcon('inbox');
export const Bell = createIcon('bell');
export const Moon = createIcon('moon');
export const Sun = createIcon('sun');
export const Monitor = createIcon('monitor');
export const Home = createIcon('home');
export const HelpCircle = createIcon('help');
export const CreditCard = createIcon('credit-card');
export const Euro = createIcon('euro');
export const Menu = createIcon('menu');
export const LogOut = createIcon('logout');
export const MoreHorizontal = createIcon('more');
export const Loader2 = createIcon('spinner');
export const Lightbulb = createIcon('lightbulb');
export const Brain = createIcon('brain');
export const Gauge = createIcon('gauge');
export const Webhook = createIcon('webhook');
export const Hash = createIcon('hash');
export const Link = createIcon('link');
export const Trophy = createIcon('trophy');
export const Calculator = createIcon('calculator');
export const DollarSign = createIcon('dollar');
export const TrendingUp = createIcon('trend-up');
export const TrendingDown = createIcon('trend-down');
export const Clipboard = createIcon('clipboard');
export const PhoneCall = createIcon('phone-line');
export const Folder = createIcon('folder');
export const PhoneCallIcon = PhoneCall;
export const ArrowDownRightIcon = ArrowDownRight;
export const ArrowUpRightIcon = ArrowUpRight;
export const Spark = createIcon('spark');
