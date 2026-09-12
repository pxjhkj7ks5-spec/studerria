'use strict';

class BaseCollector {
  constructor({ name, platform, capabilities = [], rateLimit = null }) {
    if (new.target === BaseCollector) throw new Error('BaseCollector is abstract');
    this.name = name;
    this.platform = platform;
    this.capabilities = Object.freeze([...capabilities]);
    this.rateLimit = rateLimit;
  }

  async collect() { throw new Error('collect() must be implemented'); }

  normalize(payload) { return payload; }

  describe() {
    return { name: this.name, platform: this.platform, capabilities: this.capabilities, rateLimit: this.rateLimit };
  }
}

module.exports = { BaseCollector };
