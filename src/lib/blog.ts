import type { BlogPost } from '../types/post'
import rawPosts from 'virtual:blog-data'

export const allPosts: BlogPost[] = rawPosts as BlogPost[]

export function getPostBySlug(slug: string): BlogPost | undefined {
  return allPosts.find(p => p.slug === slug)
}
