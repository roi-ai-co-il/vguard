import { useEffect, useRef, useState } from 'react'
import { motion, useInView } from 'framer-motion'
import { cn } from '@/lib/utils'

interface TypingEffectProps {
  texts?: string[]
  className?: string
  cursorClassName?: string
  rotationInterval?: number
  typingSpeed?: number
}

const DEMO = ['Design', 'Development', 'Marketing']

export const TypingEffect = ({
  texts = DEMO,
  className,
  cursorClassName,
  rotationInterval = 3000,
  typingSpeed = 150,
}: TypingEffectProps) => {
  const [displayedText, setDisplayedText] = useState('')
  const [currentTextIndex, setCurrentTextIndex] = useState(0)
  const [charIndex, setCharIndex] = useState(0)
  const containerRef = useRef<HTMLSpanElement>(null)
  const isInView = useInView(containerRef, { once: true })

  const currentText = texts[currentTextIndex % texts.length]
  const maxLen = texts.reduce((m, t) => Math.max(m, t.length), 0)

  useEffect(() => {
    if (!isInView) return

    if (charIndex < currentText.length) {
      const typingTimeout = setTimeout(() => {
        setDisplayedText((prev) => prev + currentText.charAt(charIndex))
        setCharIndex(charIndex + 1)
      }, typingSpeed)
      return () => clearTimeout(typingTimeout)
    } else {
      const changeLabelTimeout = setTimeout(() => {
        setDisplayedText('')
        setCharIndex(0)
        setCurrentTextIndex((prev) => (prev + 1) % texts.length)
      }, rotationInterval)
      return () => clearTimeout(changeLabelTimeout)
    }
  }, [charIndex, currentText, isInView, rotationInterval, typingSpeed, texts.length])

  return (
    <span
      ref={containerRef}
      className={cn('relative inline-flex items-baseline', className)}
      style={{ minWidth: `${maxLen}ch` }}
    >
      <span aria-live="polite">{displayedText}</span>
      <motion.span
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{
          duration: 0.8,
          repeat: Infinity,
          repeatType: 'reverse',
        }}
        className={cn('ml-1 inline-block h-[0.9em] w-[3px] rounded-sm bg-current align-baseline', cursorClassName)}
      />
    </span>
  )
}

export default TypingEffect
