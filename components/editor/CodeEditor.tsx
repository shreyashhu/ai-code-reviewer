'use client';

import { useRef, useCallback, useEffect, memo } from 'react';
import { cn } from '@/lib/utils';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language: string;
  bugLines?: number[];
  onFocusRef?: React.MutableRefObject<(() => void) | null>;
  className?: string;
}

export const CodeEditor = memo(function CodeEditor({
  value,
  onChange,
  language,
  bugLines = [],
  onFocusRef,
  className,
}: CodeEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);

  // Expose focus() via ref
  useEffect(() => {
    if (onFocusRef) {
      onFocusRef.current = () => textareaRef.current?.focus();
    }
  }, [onFocusRef]);

  // Sync line numbers scroll with textarea scroll
  const syncScroll = useCallback(() => {
    if (lineNumbersRef.current && textareaRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  }, []);

  const lines = value.split('\n');
  const lineCount = lines.length;

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => onChange(e.target.value),
    [onChange]
  );

  // Handle Tab key
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const ta = e.currentTarget;
      const start = ta.selectionStart;
      const end = ta.selectionEnd;
      const newVal = ta.value.substring(0, start) + '  ' + ta.value.substring(end);
      onChange(newVal);
      // Restore cursor
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = start + 2;
      });
    }
  }, [onChange]);

  return (
    <div
      className={cn('flex w-full h-full overflow-hidden', className)}
      style={{ background: '#0d0d10', fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace' }}
    >
      {/* Line numbers */}
      <div
        ref={lineNumbersRef}
        aria-hidden="true"
        className="overflow-hidden flex-shrink-0 select-none"
        style={{
          width: 48,
          background: '#0d0d10',
          borderRight: '1px solid rgba(255,255,255,0.05)',
          paddingTop: 16,
          paddingBottom: 16,
          overflowY: 'hidden',
        }}
      >
        {Array.from({ length: lineCount }, (_, i) => {
          const lineNum = i + 1;
          const isBug = bugLines.includes(lineNum);
          return (
            <div
              key={i}
              style={{
                height: 22,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                paddingRight: 12,
                fontSize: 12,
                lineHeight: '22px',
                color: isBug ? '#ef4444' : '#3f3f46',
                background: isBug ? 'rgba(239,68,68,0.08)' : 'transparent',
              }}
            >
              {isBug ? '⚠' : lineNum}
            </div>
          );
        })}
      </div>

      {/* The actual editable area */}
      <textarea
        ref={textareaRef}
        value={value}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onScroll={syncScroll}
        spellCheck={false}
        autoCapitalize="off"
        autoCorrect="off"
        autoComplete="off"
        data-gramm="false"
        placeholder={`// Paste or type your ${language} code here…`}
        className="flex-1 resize-none outline-none border-none bg-transparent overflow-auto"
        style={{
          fontSize: 13,
          lineHeight: '22px',
          color: '#e4e4e7',
          caretColor: '#a78bfa',
          paddingTop: 16,
          paddingBottom: 16,
          paddingLeft: 16,
          paddingRight: 16,
          fontFamily: 'inherit',
          letterSpacing: '0.01em',
          tabSize: 2,
          // Prevent any browser interference
          WebkitTextFillColor: '#e4e4e7',
        }}
      />
    </div>
  );
});
