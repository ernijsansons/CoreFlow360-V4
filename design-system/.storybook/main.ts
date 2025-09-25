import type { StorybookConfig } from '@storybook/react-vite';

const config: StorybookConfig = {
  stories: [
    '../**/*.stories.@(js|jsx|ts|tsx|mdx)',
    '../**/*.mdx',
  ],
  addons: [
    '@storybook/addon-essentials',
    '@storybook/addon-interactions',
    '@storybook/addon-a11y',
    '@storybook/addon-viewport',
    '@storybook/addon-measure',
    '@storybook/addon-outline',
    'storybook-dark-mode',
    '@storybook/addon-designs',
  ],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  core: {
    disableTelemetry: true,
  },
  features: {
    storyStoreV7: true,
  },
  staticDirs: ['../public'],
  viteFinal: async (config) => {
    // Customize Vite config
    config.define = {
      ...config.define,
      'process.env': {},
    };
    return config;
  },
};

export default config;