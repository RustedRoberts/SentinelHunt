import { HashRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import HuntDetail from './pages/HuntDetail'
import Coverage from './pages/Coverage'
import Methodology from './pages/Methodology'

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/hunt/:id" element={<HuntDetail />} />
        <Route path="/coverage" element={<Coverage />} />
        <Route path="/methodology" element={<Methodology />} />
      </Routes>
    </HashRouter>
  )
}
