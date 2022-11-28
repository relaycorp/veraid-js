import mainJestConfig from './jest.config.mjs';

const CONFIG = {
  ...mainJestConfig,
  moduleFileExtensions: ['js'],
  preset: null,
  roots: ['build/lib/integrationTests']
};

export default CONFIG;
