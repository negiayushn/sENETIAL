import { forwardRef, InputHTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => (
  <input
    ref={ref}
    className={cn(
      'h-9 w-full rounded-md border border-line bg-bg px-3 text-sm text-fg placeholder:text-muted/70 focus:border-accent',
      className,
    )}
    {...p}
  />
));
Input.displayName = 'Input';
