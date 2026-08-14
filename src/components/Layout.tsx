import Nav from './Nav'
import SmokeBackground from './SmokeBackground'

interface LayoutProps {
  children: React.ReactNode
  className?: string
}

export default function Layout({ children, className = '' }: LayoutProps) {
  return (
    <div className="min-h-screen bg-[#111111]">
      <SmokeBackground />
      <Nav />
      <main className={['max-w-7xl mx-auto px-6 py-10', className].join(' ')}>
        {children}
      </main>
    </div>
  )
}
