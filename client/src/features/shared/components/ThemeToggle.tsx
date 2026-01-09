import { Moon, Sun } from 'lucide-react'
import React from 'react'
import { useTheme } from './ThemeProvider';
import { Button } from './ui/Button';

const ThemeToggle = () => {
    const { theme, setTheme } = useTheme();

  return (
    <>
      <Button variant="ghost" size="icon" className="justify-start p-2" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
        {theme === 'dark' ? <>
            <Sun className="h-6 w-6" />
            Light mode
        </> : <>
            <Moon className="h-6 w-6" />
            Dark mode
        </>}
      </Button>
    </>
  )
}

export default ThemeToggle
