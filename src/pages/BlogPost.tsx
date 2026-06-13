import { Link, useParams, Navigate } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import Layout from '../components/Layout'
import { getPostBySlug } from '../lib/blog'

function formatDate(date: string): string {
  return new Date(date).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })
}

export default function BlogPost() {
  const { slug } = useParams<{ slug: string }>()
  const post = slug ? getPostBySlug(slug) : undefined

  if (!post) return <Navigate to="/blog" replace />

  return (
    <Layout className="max-w-2xl">
      <div className="mb-6">
        <Link to="/blog" className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">
          ← Blog
        </Link>
      </div>

      <header className="mb-8 pb-6 border-b border-[#2a2a2a]">
        {post.tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-4">
            {post.tags.map(tag => (
              <span
                key={tag}
                className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium font-mono bg-zinc-800 text-zinc-400"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
        <h1 className="font-display text-4xl font-bold text-zinc-100 mb-4 leading-tight">
          {post.title}
        </h1>
        <div className="flex items-center gap-2 text-sm text-zinc-500">
          <span>{post.author}</span>
          <span className="text-zinc-700">·</span>
          <span>{formatDate(post.date)}</span>
          <span className="text-zinc-700">·</span>
          <span>{post.readingTime} min read</span>
        </div>
      </header>

      {post.coverImage && (
        <img
          src={post.coverImage}
          alt=""
          className="w-full rounded-lg border border-[#2a2a2a] mb-8"
        />
      )}

      <div className="prose prose-hunt prose-lg max-w-none">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{post.content}</ReactMarkdown>
      </div>
    </Layout>
  )
}
