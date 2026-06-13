export interface BlogPost {
  slug: string
  title: string
  date: string
  author: string
  summary: string
  tags: string[]
  published: boolean
  coverImage?: string
  content: string
  readingTime: number
}
