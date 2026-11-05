import type { CSSProperties } from 'react';

export type IconName = 'overview' | 'report' | 'review' | 'feed' | 'arrow' | 'check' | 'shield' | 'refresh' | 'logout' | 'menu' | 'close' | 'clock' | 'alert' | 'search' | 'chevron' | 'lock' | 'plus' | 'eye' | 'users' | 'layers' | 'database' | 'cpu' | 'link' | 'terminal';
const paths: Record<IconName, string[]> = {
  overview: ['M3 3h7v7H3z', 'M14 3h7v7h-7z', 'M3 14h7v7H3z', 'M14 14h7v7h-7z'],
  report: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6', 'M8 13h8', 'M8 17h5'],
  review: ['M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2h-4', 'M9 2h6v4H9z', 'M8 13l3 3 5-6'],
  feed: ['M4 3h16v18H4z', 'M8 7h8', 'M8 11h8', 'M8 15h5'],
  arrow: ['M4 12h16', 'm14 6 6 6-6 6'], check: ['m5 12 4 4L19 6'],
  shield: ['M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z', 'm8 12 3 3 5-6'],
  refresh: ['M20 7v5h-5', 'M4 17v-5h5', 'M6 6a8 8 0 0 1 13 2l1 4', 'M18 18a8 8 0 0 1-13-2l-1-4'],
  logout: ['M9 4H4v16h5', 'M9 12h12', 'm17 8 4 4-4 4'], menu: ['M3 6h18', 'M3 12h18', 'M3 18h18'],
  close: ['m6 6 12 12', 'M18 6 6 18'], clock: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18', 'M12 7v5l3 2'],
  alert: ['m12 3 10 18H2z', 'M12 9v5', 'M12 17v.01'], search: ['M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14', 'm15 15 6 6'],
  chevron: ['m9 5 7 7-7 7'], lock: ['M5 10h14v11H5z', 'M8 10V7a4 4 0 0 1 8 0v3'], plus: ['M12 5v14', 'M5 12h14'],
  eye: ['M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6'],
  users: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8', 'M22 21v-2a4 4 0 0 0-3-3.87', 'M16 3.13a4 4 0 0 1 0 7.75'],
  layers: ['m12 2 10 5-10 5L2 7z', 'm2 17 10 5 10-5', 'm2 12 10 5 10-5'],
  database: ['M3 6a9 3 0 1 0 18 0 9 3 0 1 0-18 0', 'M3 6v12a9 3 0 0 0 18 0V6', 'M3 12a9 3 0 0 0 18 0'],
  cpu: ['M6 6h12v12H6z', 'M9.5 9.5h5v5h-5z', 'M9 2v4', 'M15 2v4', 'M9 18v4', 'M15 18v4', 'M2 9h4', 'M2 15h4', 'M18 9h4', 'M18 15h4'],
  link: ['M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7', 'M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7'],
  terminal: ['M3 4h18v16H3z', 'm7 9 3 3-3 3', 'M13 15h4'],
};
export function Icon({ name, size = 20, style }: { name: IconName; size?: number; style?: CSSProperties }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={style}>{paths[name].map((d, i) => <path d={d} key={i} />)}</svg>;
}
