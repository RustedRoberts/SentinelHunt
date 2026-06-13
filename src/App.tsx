import { HashRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import HuntDetail from './pages/HuntDetail'
import Coverage from './pages/Coverage'
import Methodology from './pages/Methodology'
import Investigation from './pages/Investigation'
import Blog from './pages/Blog'
import BlogPost from './pages/BlogPost'

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/hunt/:id" element={<HuntDetail />} />
        <Route path="/investigation" element={<Investigation />} />
        <Route path="/coverage" element={<Coverage />} />
        <Route path="/methodology" element={<Methodology />} />
        <Route path="/blog" element={<Blog />} />
        <Route path="/blog/:slug" element={<BlogPost />} />
      </Routes>
    </HashRouter>
  )
}
