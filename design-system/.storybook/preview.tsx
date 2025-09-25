import type { Preview } from '@storybook/react';
import React from 'react';
import { themes } from '@storybook/theming';
import '../styles/globals.css';

const preview: Preview = {
  parameters: {
    actions: { argTypesRegex: '^on[A-Z].*' },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/,
      },
    },
    darkMode: {
      dark: {
        ...themes.dark,
        appBg: '#000000',
        appContentBg: '#0A0A0A',
        appBorderColor: 'rgba(255, 255, 255, 0.08)',
        barBg: '#000000',
        brandTitle: 'The Future of Enterprise',
        brandUrl: '/',
        brandImage: '/logo-dark.svg',
      },
      light: {
        ...themes.light,
        appBg: '#FFFFFF',
        appContentBg: '#FAFAFA',
        appBorderColor: 'rgba(0, 0, 0, 0.08)',
        barBg: '#FFFFFF',
        brandTitle: 'The Future of Enterprise',
        brandUrl: '/',
        brandImage: '/logo-light.svg',
      },
      current: 'dark',
    },
    viewport: {
      viewports: {
        iphone14: {
          name: 'iPhone 14',
          styles: {
            width: '390px',
            height: '844px',
          },
        },
        ipad: {
          name: 'iPad',
          styles: {
            width: '768px',
            height: '1024px',
          },
        },
        desktop: {
          name: 'Desktop',
          styles: {
            width: '1440px',
            height: '900px',
          },
        },
        ultrawide: {
          name: 'Ultrawide',
          styles: {
            width: '2560px',
            height: '1080px',
          },
        },
      },
    },
    backgrounds: {
      default: 'dark',
      values: [
        {
          name: 'dark',
          value: '#000000',
        },
        {
          name: 'light',
          value: '#FFFFFF',
        },
        {
          name: 'gray',
          value: '#0A0A0A',
        },
      ],
    },
    docs: {
      theme: themes.dark,
    },
  },
  decorators: [
    (Story, context) => {
      const theme = context.globals.theme || 'dark';
      return (
        <div className={theme}>
          <div className="min-h-screen bg-white dark:bg-black text-black dark:text-white">
            <Story />
          </div>
        </div>
      );
    },
  ],
  globalTypes: {
    theme: {
      name: 'Theme',
      description: 'Global theme for components',
      defaultValue: 'dark',
      toolbar: {
        icon: 'circlehollow',
        items: ['light', 'dark'],
        showName: true,
        dynamicTitle: true,
      },
    },
  },
};

export default preview;