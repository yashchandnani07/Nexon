import { useEffect, useRef, useState } from 'react'

/**
 * Animates a number from 0 to `end` over `duration` ms.
 * Returns the current animated value as a string.
 */
export function useCountUp(end, duration = 1200, suffix = '') {
  const [count, setCount] = useState(0)
  const raf = useRef(null)

  useEffect(() => {
    const startTime = performance.now()
    const startVal  = 0
    const endVal    = parseFloat(String(end).replace(/[^0-9.]/g, ''))

    const tick = (now) => {
      const elapsed  = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      // ease-out cubic
      const eased    = 1 - Math.pow(1 - progress, 3)
      const current  = startVal + (endVal - startVal) * eased

      // Preserve decimal places from original `end`
      const decimals = String(end).includes('.') ? String(end).split('.')[1].length : 0
      setCount(parseFloat(current.toFixed(decimals)))

      if (progress < 1) raf.current = requestAnimationFrame(tick)
    }

    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [end, duration])

  const raw = String(end)

  // If there are no digits at all (e.g. value is '—' placeholder), return as-is
  if (!/\d/.test(raw)) return raw

  const prefix = raw.match(/^[^0-9]*/)?.[0] ?? ''
  const displaySuffix = suffix || (raw.match(/[^0-9.]+$/)?.[0] ?? '')

  return `${prefix}${count}${displaySuffix}`
}
