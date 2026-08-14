import Nav from './Nav'
import WireMeshBackground from './WireMeshBackground'

interface LayoutProps {
  children: React.ReactNode
  className?: string
}

export default function Layout({ children, className = '' }: LayoutProps) {
  return (
    <div className="min-h-screen">
      <WireMeshBackground />
      <Nav />
      <main className={['max-w-7xl mx-auto px-6 py-10', className].join(' ')}>
        {children}
      </main>
    </div>
  )
}
