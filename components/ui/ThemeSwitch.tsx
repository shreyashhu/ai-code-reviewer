'use client';

import { Moon, Sun } from 'lucide-react';
import { cn } from '@/lib/utils';

type Theme = 'dark' | 'light';

interface ThemeSwitchProps {
  value: Theme;
  onChange: (theme: Theme) => void;
  className?: string;
}

/** A visible two-state control rather than a hidden preference behind one icon. */
export function ThemeSwitch({ value, onChange, className }: ThemeSwitchProps) {
  return (
    <div className={cn('theme-switch', className)} aria-label="Appearance">
      <button
        type="button"
        aria-pressed={value === 'light'}
        onClick={() => onChange('light')}
        className={cn('theme-option', value === 'light' && 'is-active')}
        title="Use light theme"
      >
        <Sun className="w-3.5 h-3.5" />
        <span className="hidden xl:inline">Light</span>
      </button>
      <button
        type="button"
        aria-pressed={value === 'dark'}
        onClick={() => onChange('dark')}
        className={cn('theme-option', value === 'dark' && 'is-active')}
        title="Use dark theme"
      >
        <Moon className="w-3.5 h-3.5" />
        <span className="hidden xl:inline">Dark</span>
      </button>
    </div>
  );
}
