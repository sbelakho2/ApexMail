import * as React from 'react';

export interface ApexIconProps extends React.SVGProps<SVGSVGElement> {
  size?: number;
  strokeWidth?: number;
}

export type ApexIconComponent = React.FC<ApexIconProps>;

type Glyph =
  | 'arrow-right'
  | 'chevron-right'
  | 'check'
  | 'x'
  | 'badge'
  | 'lock'
  | 'key'
  | 'mail'
  | 'user'
  | 'users'
  | 'bot'
  | 'search'
  | 'alert'
  | 'calendar'
  | 'settings'
  | 'bar-chart'
  | 'eye'
  | 'code'
  | 'terminal'
  | 'cloud'
  | 'server'
  | 'database'
  | 'globe'
  | 'phone'
  | 'book'
  | 'building'
  | 'ticket'
  | 'tag'
  | 'flag'
  | 'flame'
  | 'target'
  | 'activity'
  | 'history'
  | 'file'
  | 'download'
  | 'upload'
  | 'trash'
  | 'pencil'
  | 'list-filter'
  | 'inbox'
  | 'bell'
  | 'home'
  | 'help'
  | 'credit-card'
  | 'euro'
  | 'menu'
  | 'more'
  | 'spinner';

const glyphs: Record<Glyph, React.ReactNode> = {
  'arrow-right': <path d="M5 12h12m-4-4 4 4-4 4" />,
  'chevron-right': <path d="m9 6 6 6-6 6" />,
  check: <path d="M6 12l4 4 8-8" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  badge: <path d="M12 3l7 3v6c0 4.2-3.2 6.6-7 9-3.8-2.4-7-4.8-7-9V6l7-3z" />,
  lock: <path d="M7 11h10v8H7zM9 11V8a3 3 0 0 1 6 0v3" />,
  key: <path d="M14 10a3 3 0 1 1-6 0 3 3 0 0 1 6 0zm0 0h6v4h-4" />,
  mail: <path d="M4 6h16v12H4zM4 7l8 6 8-6" />,
  user: <path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4zm-6 7c1.5-3 10.5-3 12 0" />,
  users: <path d="M8 11a3 3 0 1 0-3-3 3 3 0 0 0 3 3zm8 0a3 3 0 1 0-3-3 3 3 0 0 0 3 3M4 19c1.2-2.4 7-2.8 8-1m2 1c1-1.8 5.6-2.2 6-1" />,
  bot: <path d="M7 7h10v10H7zM9 11h.01M15 11h.01M10 15h4" />,
  search: <path d="M11 5a6 6 0 1 0 0 12 6 6 0 0 0 0-12zm8 14-4-4" />,
  alert: <path d="M12 5 20 19H4zM12 10v4m0 3h.01" />,
  calendar: <path d="M6 7h12v12H6zM8 4v3m8-3v3M6 10h12" />,
  settings: <path d="M4 7h9m3 0h4M8 7v2m4 8H4m14 0h2m-6 0v2" />,
  'bar-chart': <path d="M6 18V9m6 9V6m6 12v-4" />,
  eye: <path d="M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6zm9 3a3 3 0 1 0-3-3 3 3 0 0 0 3 3z" />,
  code: <path d="M9 8 5 12l4 4m6-8 4 4-4 4" />,
  terminal: <path d="M4 6h16v12H4zM7 10l3 2-3 2m6 2h4" />,
  cloud: <path d="M7 18h9a4 4 0 0 0 .5-8 5 5 0 0 0-9.7 1A3.5 3.5 0 0 0 7 18z" />,
  server: <path d="M5 6h14v4H5zM5 14h14v4H5z" />,
  database: <path d="M5 7c0-2 14-2 14 0v10c0 2-14 2-14 0zM5 11c0 2 14 2 14 0" />,
  globe: <path d="M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 0c2.5 2.2 2.5 9.8 0 12m0-12c-2.5 2.2-2.5 9.8 0 12M4 12h16" />,
  phone: <path d="M7 4h10v16H7zM11 16h2" />,
  book: <path d="M5 6h7v12H5zM12 6h7v12h-7M8 8h2M15 8h2" />,
  building: <path d="M5 5h14v14H5zM9 9h2m4 0h2M9 13h2m4 0h2" />,
  ticket: <path d="M5 7h14v3a2 2 0 0 1 0 4v3H5v-3a2 2 0 0 0 0-4V7z" />,
  tag: <path d="M4 10l6-6h6l4 4v6l-6 6-10-10z" />,
  flag: <path d="M5 4v16m0-14h10l-2 3 2 3H5" />,
  flame: <path d="M12 4c3 4 2 5.5 0 7-2 1.5-2 4 0 6-4 0-6-3-6-6 0-3 2-5 6-7z" />,
  target: <path d="M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zm0 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8" />,
  activity: <path d="M4 12h4l2-4 3 8 3-6h4" />,
  history: <path d="M5 12a7 7 0 1 0 3-5.7M5 12V7h5m2 1v5l3 2" />,
  file: <path d="M7 4h7l3 3v13H7zM14 4v3h3" />,
  download: <path d="M12 5v10m0 0-4-4m4 4 4-4M5 19h14" />,
  upload: <path d="M12 19V9m0 0-4 4m4-4 4 4M5 5h14" />,
  trash: <path d="M6 7h12m-9 0 1 12h6l1-12M9 7V5h6v2" />,
  pencil: <path d="M5 19h4l9-9-4-4-9 9v4zm9-12 4 4" />,
  'list-filter': <path d="M4 7h16M7 12h10M10 17h4" />,
  inbox: <path d="M4 6h16v10h-5l-3 3-3-3H4z" />,
  bell: <path d="M12 5a4 4 0 0 1 4 4v4l2 3H6l2-3V9a4 4 0 0 1 4-4zm0 14a2 2 0 0 0 2-2h-4a2 2 0 0 0 2 2z" />,
  home: <path d="M4 12l8-7 8 7v7H4zM9 19v-6h6v6" />,
  help: <path d="M12 18h.01M9.5 9a3 3 0 1 1 5 2.2c-.8.5-1.5 1.1-1.5 2.3" />,
  'credit-card': <path d="M4 7h16v10H4zM4 10h16M7 15h4" />,
  euro: <path d="M16 7a4 4 0 0 0-4-2 4 4 0 0 0 0 8 4 4 0 0 0 4-2M6 10h6M6 14h6" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  more: <path d="M6 12h.01M12 12h.01M18 12h.01" />,
  spinner: <path d="M12 4a8 8 0 1 1-5.6 2.4" />,
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
export const ChevronRight = createIcon('chevron-right');
export const Check = createIcon('check');
export const CheckCircle = createIcon('check');
export const CheckCircle2 = createIcon('check');
export const X = createIcon('x');
export const Shield = createIcon('badge');
export const ShieldCheck = createIcon('badge');
export const Lock = createIcon('lock');
export const Key = createIcon('key');
export const Mail = createIcon('mail');
export const Users = createIcon('users');
export const Bot = createIcon('bot');
export const Search = createIcon('search');
export const AlertTriangle = createIcon('alert');
export const Calendar = createIcon('calendar');
export const Settings = createIcon('settings');
export const BarChart3 = createIcon('bar-chart');
export const Eye = createIcon('eye');
export const Code = createIcon('code');
export const Terminal = createIcon('terminal');
export const Cloud = createIcon('cloud');
export const Server = createIcon('server');
export const Database = createIcon('database');
export const Globe = createIcon('globe');
export const Phone = createIcon('phone');
export const BookOpen = createIcon('book');
export const Building2 = createIcon('building');
export const Ticket = createIcon('ticket');
export const Tag = createIcon('tag');
export const Flag = createIcon('flag');
export const Flame = createIcon('flame');
export const Target = createIcon('target');
export const Activity = createIcon('activity');
export const History = createIcon('history');
export const FileText = createIcon('file');
export const Download = createIcon('download');
export const Upload = createIcon('upload');
export const Trash2 = createIcon('trash');
export const Pencil = createIcon('pencil');
export const ListFilter = createIcon('list-filter');
export const Inbox = createIcon('inbox');
export const Bell = createIcon('bell');
export const Home = createIcon('home');
export const HelpCircle = createIcon('help');
export const CreditCard = createIcon('credit-card');
export const Euro = createIcon('euro');
export const Menu = createIcon('menu');
export const MoreHorizontal = createIcon('more');
export const Loader2 = createIcon('spinner');
