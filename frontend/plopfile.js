export default function (plop) {
  plop.setGenerator('component', {
    description: 'Create a new component',
    prompts: [
      {
        type: 'input',
        name: 'name',
        message: 'Component name:',
      },
      {
        type: 'list',
        name: 'type',
        message: 'Component type:',
        choices: ['ui', 'feature', 'layout', 'module'],
      },
      {
        type: 'confirm',
        name: 'hasTest',
        message: 'Include test file?',
        default: true,
      },
      {
        type: 'confirm',
        name: 'hasStory',
        message: 'Include Storybook story?',
        default: true,
      },
    ],
    actions: function (data) {
      const actions = []
      const componentPath = data.type === 'ui'
        ? 'src/components/ui'
        : data.type === 'module'
        ? 'src/modules/{{dashCase name}}/components'
        : 'src/components/{{dashCase name}}'

      actions.push({
        type: 'add',
        path: `${componentPath}/{{dashCase name}}.tsx`,
        templateFile: 'plop-templates/component.tsx.hbs',
      })

      if (data.hasTest) {
        actions.push({
          type: 'add',
          path: `${componentPath}/__tests__/{{dashCase name}}.test.tsx`,
          templateFile: 'plop-templates/component.test.tsx.hbs',
        })
      }

      if (data.hasStory) {
        actions.push({
          type: 'add',
          path: `${componentPath}/{{dashCase name}}.stories.tsx`,
          templateFile: 'plop-templates/component.stories.tsx.hbs',
        })
      }

      return actions
    },
  })

  plop.setGenerator('hook', {
    description: 'Create a new React hook',
    prompts: [
      {
        type: 'input',
        name: 'name',
        message: 'Hook name (without "use" prefix):',
      },
    ],
    actions: [
      {
        type: 'add',
        path: 'src/hooks/use-{{dashCase name}}.tsx',
        templateFile: 'plop-templates/hook.tsx.hbs',
      },
      {
        type: 'add',
        path: 'src/hooks/__tests__/use-{{dashCase name}}.test.tsx',
        templateFile: 'plop-templates/hook.test.tsx.hbs',
      },
    ],
  })

  plop.setGenerator('store', {
    description: 'Create a new Zustand store',
    prompts: [
      {
        type: 'input',
        name: 'name',
        message: 'Store name (without "store" suffix):',
      },
    ],
    actions: [
      {
        type: 'add',
        path: 'src/stores/{{dashCase name}}-store.ts',
        templateFile: 'plop-templates/store.ts.hbs',
      },
    ],
  })

  plop.setGenerator('module', {
    description: 'Create a new feature module',
    prompts: [
      {
        type: 'input',
        name: 'name',
        message: 'Module name:',
      },
    ],
    actions: [
      {
        type: 'add',
        path: 'src/modules/{{dashCase name}}/index.ts',
        templateFile: 'plop-templates/module/index.ts.hbs',
      },
      {
        type: 'add',
        path: 'src/modules/{{dashCase name}}/components/index.ts',
        templateFile: 'plop-templates/module/components-index.ts.hbs',
      },
      {
        type: 'add',
        path: 'src/modules/{{dashCase name}}/hooks/index.ts',
        templateFile: 'plop-templates/module/hooks-index.ts.hbs',
      },
      {
        type: 'add',
        path: 'src/modules/{{dashCase name}}/types.ts',
        templateFile: 'plop-templates/module/types.ts.hbs',
      },
      {
        type: 'add',
        path: 'src/modules/{{dashCase name}}/api.ts',
        templateFile: 'plop-templates/module/api.ts.hbs',
      },
    ],
  })
}