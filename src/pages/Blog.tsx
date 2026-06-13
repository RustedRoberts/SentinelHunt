import { Link } from 'react-router-dom'
import Layout from '../components/Layout'
import { allPosts } from '../lib/blog'

function formatDate(date: string): string {
  return new Date(date).toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })
}

export default function Blog() {
  return (
    <Layout className="max-w-3xl">
      <div className="mb-10">
        <h1 className="font-display text-4xl font-bold text-zinc-100 mb-2">Blog</h1>
        <p className="text-zinc-400 text-lg max-w-2xl">
          Notes, write-ups, and field observations from building SentinelHunt.
        </p>
      </div>

      {allPosts.length === 0 ? (
        <div className="text-center py-20 text-zinc-600">
          <p className="text-lg">No posts published yet.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-8">
          {allPosts.map(post => (
            <Link
              key={post.slug}
              to={`/blog/${post.slug}`}
              className="group block pb-8 border-b border-[#2a2a2a] last:border-b-0 last:pb-0"
            >
              <div className="flex items-center gap-2 mb-2 text-xs text-zinc-500">
                <span>{formatDate(post.date)}</span>
                <span className="text-zinc-700">·</span>
                <span>{post.readingTime} min read</span>
              </div>
              <h2 className="font-display text-2xl font-bold text-zinc-100 group-hover:text-[#d4ff3f] transition-colors mb-2 leading-snug">
                {post.title}
              </h2>
              <p className="text-zinc-400 leading-relaxed mb-3 max-w-2xl">{post.summary}</p>
              <div className="flex items-center gap-3">
                <span className="text-sm text-zinc-500">{post.author}</span>
                {post.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
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
              </div>
            </Link>
          ))}
        </div>
      )}
    </Layout>
  )
}
