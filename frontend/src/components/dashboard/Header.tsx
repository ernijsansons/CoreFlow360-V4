import React from 'react';
import { Menu, Moon, Sun, Bell, Search } from 'lucide-react';
import { useDashboardStore } from '@/stores/dashboardStore';
import { useAuthStore } from '@/stores/authStore';
import { useDarkMode } from '@/hooks/useDarkMode';

/**
 * Dashboard header with user profile, theme toggle, and mobile menu
 */
export const Header: React.FC = () => {
  const { toggleSidebar } = useDashboardStore();
  const { user } = useAuthStore();
  const { darkMode, toggleDarkMode } = useDarkMode();

  return (
    <header className="sticky top-0 z-30 flex w-full bg-white drop-shadow-1 dark:bg-boxdark dark:drop-shadow-none">
      <div className="flex flex-grow items-center justify-between px-4 py-4 shadow-2 md:px-6 2xl:px-11">
        {/* Mobile Menu Toggle */}
        <div className="flex items-center gap-2 sm:gap-4 lg:hidden">
          <button
            onClick={toggleSidebar}
            className="z-50 block rounded-sm border border-stroke bg-white p-1.5 shadow-sm dark:border-strokedark dark:bg-boxdark lg:hidden"
            aria-label="Toggle menu"
          >
            <Menu className="h-5.5 w-5.5" />
          </button>
        </div>

        {/* Search Bar (Desktop) */}
        <div className="hidden sm:block">
          <form className="relative">
            <button className="absolute left-0 top-1/2 -translate-y-1/2 pl-4">
              <Search className="h-5 w-5 text-bodydark dark:text-bodydark1" />
            </button>
            <input
              type="text"
              placeholder="Type to search..."
              className="w-full bg-transparent pl-12 pr-4 text-black focus:outline-none dark:text-white xl:w-125"
            />
          </form>
        </div>

        {/* Right Side: Theme Toggle, Notifications, User */}
        <div className="flex items-center gap-3 2xsm:gap-7">
          {/* Dark Mode Toggle */}
          <button
            onClick={toggleDarkMode}
            className="flex h-8.5 w-8.5 items-center justify-center rounded-full border-[0.5px] border-stroke bg-gray hover:bg-gray-2 dark:border-strokedark dark:bg-meta-4 dark:hover:bg-boxdark"
            aria-label="Toggle dark mode"
          >
            {darkMode ? (
              <Sun className="h-5 w-5 text-bodydark" />
            ) : (
              <Moon className="h-5 w-5 text-bodydark" />
            )}
          </button>

          {/* Notifications */}
          <button
            className="relative flex h-8.5 w-8.5 items-center justify-center rounded-full border-[0.5px] border-stroke bg-gray hover:bg-gray-2 dark:border-strokedark dark:bg-meta-4 dark:hover:bg-boxdark"
            aria-label="Notifications"
          >
            <Bell className="h-5 w-5 text-bodydark" />
            <span className="absolute -top-0.5 -right-0.5 z-1 h-2 w-2 rounded-full bg-meta-1">
              <span className="absolute -z-1 inline-flex h-full w-full animate-ping rounded-full bg-meta-1 opacity-75"></span>
            </span>
          </button>

          {/* User Dropdown */}
          <div className="relative">
            <button className="flex items-center gap-4">
              <span className="hidden text-right lg:block">
                <span className="block text-sm font-medium text-black dark:text-white">
                  {user?.name || 'User'}
                </span>
                <span className="block text-xs">{user?.role || 'Admin'}</span>
              </span>

              <span className="h-12 w-12 overflow-hidden rounded-full">
                {user?.avatar ? (
                  <img src={user.avatar} alt={user.name} className="h-full w-full object-cover" />
                ) : (
                  <div className="flex h-full w-full items-center justify-center bg-brand-primary-600 text-white">
                    {user?.name?.charAt(0).toUpperCase() || 'U'}
                  </div>
                )}
              </span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
