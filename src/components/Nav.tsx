import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Library' },
  { to: '/coverage', label: 'Coverage' },
  { to: '/methodology', label: 'Methodology' },
]

function LinkedInIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
    </svg>
  )
}

export default function Nav() {
  return (
    <nav className="border-b border-[#2a2a2a] bg-[#111111]/90 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <a
            href="https://www.linkedin.com/in/chris-scott-ccroberts"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-zinc-500 hover:text-[#0A66C2] transition-colors"
            aria-label="Chris Scott on LinkedIn"
          >
            <LinkedInIcon />
            <span className="text-xs font-medium hidden sm:inline">Chris Scott</span>
          </a>
          <NavLink to="/" className="flex items-center gap-2 group">
            <span className="text-[#d4ff3f] font-display font-bold text-lg tracking-tight">
              SentinelHunt
            </span>
          </NavLink>
        </div>
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
          <a
            href="https://www.buymeacoffee.com/ChrisScottRoberts"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1 rounded text-sm font-medium bg-[#5F7FFF] hover:bg-[#4a6fe0] text-white transition-colors whitespace-nowrap"
          >
            ☕ <span className="hidden sm:inline">Buy me a coffee</span>
          </a>
        </div>
      </div>
    </nav>
  )
}
