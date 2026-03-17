export default function SpectraLogo({ size = 28 }) {
  return (
    <img
      src="/logo.png"
      alt="SpectraGuard"
      width={size}
      height={size}
      style={{ objectFit: 'contain', flexShrink: 0, borderRadius: 4 }}
    />
  )
}
