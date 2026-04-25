import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Library' },
  { to: '/coverage', label: 'Coverage' },
  { to: '/methodology', label: 'Methodology' },
]

export default function Nav() {
  return (
    <nav className="border-b border-[#2a2a2a] bg-[#111111]/90 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        <NavLink to="/" className="flex items-center gap-2 group">
          <span className="text-[#d4ff3f] font-display font-bold text-lg tracking-tight">
            SentinelHunt
          </span>
          <span className="text-zinc-600 text-xs font-mono uppercase tracking-widest">
            threat hunting library
          </span>
        </NavLink>
        <div className="flex items-center gap-6">
          {links.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                [
                  'text-sm font-medium transition-colors',
                  isActive ? 'text-[#d4ff3f]' : 'text-zinc-400 hover:text-zinc-100',
                ].join(' ')
              }
            >
              {label}
            </NavLink>
          ))}
        </div>
      </div>
    </nav>
  )
}
