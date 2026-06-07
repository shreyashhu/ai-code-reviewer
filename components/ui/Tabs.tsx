'use client';

import { cn } from '@/lib/utils';

export interface Tab {
  id: string;
  label: string;
  count?: number;
  icon?: React.ReactNode;
}

interface TabsProps {
  tabs: Tab[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
}

export function Tabs({ tabs, activeTab, onChange, className }: TabsProps) {
  return (
    <div className={cn('flex items-center gap-1 border-b', className)} style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
      {tabs.map((tab) => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={cn(
              'relative flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium',
              'transition-colors duration-200 rounded-t-lg whitespace-nowrap',
              isActive ? 'text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'
            )}
          >
            {tab.icon && <span className="w-3.5 h-3.5">{tab.icon}</span>}
            {tab.label}
            {tab.count !== undefined && tab.count > 0 && (
              <span className={cn(
                'inline-flex items-center justify-center min-w-4 h-4 px-1 rounded-full text-[10px] font-semibold',
                isActive ? 'bg-violet-500/20 text-violet-300' : 'bg-white/5 text-zinc-500'
              )}>
                {tab.count}
              </span>
            )}
            {isActive && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 rounded-full tab-active-line transition-all duration-200" />
            )}
          </button>
        );
      })}
    </div>
  );
}
