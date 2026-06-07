import { MetadataRoute } from 'next'

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'AI Code Reviewer',
    short_name: 'CodeReview',
    description: 'Production-grade 31-stage AI security code analyzer.',
    start_url: '/',
    display: 'standalone',
    background_color: '#0c0d19',
    theme_color: '#7cb9ff',
    icons: [
      {
        src: '/icon-512.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'any maskable'
      },
    ],
  }
}