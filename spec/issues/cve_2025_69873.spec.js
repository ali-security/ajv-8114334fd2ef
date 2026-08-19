'use strict';

var Ajv = require('../ajv');
require('../chai').should();

describe('CVE-2025-69873: ReDoS Attack via $data pattern', function() {
  var re2;
  var re2Available = false;

  before(function() {
    try {
      // re2 is an optional native addon - the concatenation keeps browserify
      // from trying to resolve it while bundling the browser tests
      re2 = require('' + 're2');
      re2.code = 'require("re2")';
      re2Available = true;
    } catch(e) {
      console.log('re2 not available, some CVE tests will be skipped');
    }
  });

  describe('with RE2 engine', function() {
    beforeEach(function() {
      if (!re2Available) this.skip();
    });

    it('should prevent ReDoS with catastrophic backtracking pattern', function() {
      var ajv = new Ajv({$data: true, regExp: re2});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      var start = Date.now();
      var result = validate({
        pattern: '^(a|a)*$',
        value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + 'X'
      });
      var elapsed = Date.now() - start;

      result.should.equal(false);
      elapsed.should.be.below(500);
    });

    it('should handle multiple ReDoS patterns', function() {
      var ajv = new Ajv({$data: true, regExp: re2});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      var redosPatterns = [
        '^(a+)+$',
        '^(a|a)*$',
        '^(a|ab)*$',
        '(x+x+)+y',
        '(a*)*b'
      ];

      redosPatterns.forEach(function(pattern) {
        var start = Date.now();
        var result = validate({
          pattern: pattern,
          value: 'aaaaaaaaaaaaaaaaaaaaaaaaa' + 'X'
        });
        var elapsed = Date.now() - start;

        elapsed.should.be.below(500, 'Pattern ' + pattern + ' took too long: ' + elapsed + 'ms');
        result.should.equal(false);
      });
    });

    it('should still validate valid patterns correctly', function() {
      var ajv = new Ajv({$data: true, regExp: re2});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      validate({pattern: '^[a-z]+$', value: 'abc'}).should.equal(true);
      validate({pattern: '^[a-z]+$', value: 'ABC'}).should.equal(false);
      validate({pattern: '^\\d{3}-\\d{4}$', value: '123-4567'}).should.equal(true);
      validate({pattern: '^\\d{3}-\\d{4}$', value: '12-345'}).should.equal(false);
    });

    it('should fail gracefully on invalid regex syntax in pattern', function() {
      var ajv = new Ajv({$data: true, regExp: re2});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      // Invalid regex patterns - should fail validation, not throw
      var result = validate({pattern: '[invalid', value: 'test'});
      result.should.equal(false);
    });

    it('should process attack payload with safe timing', function() {
      var ajv = new Ajv({$data: true, regExp: re2});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      // Process the exact CVE attack payload
      var payload = {
        pattern: '^(a|a)*$',
        value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + 'X'
      };

      // With RE2: should complete in < 100ms
      // Without RE2: would hang for 44+ seconds
      var start = Date.now();
      var result = validate(payload);
      var elapsed = Date.now() - start;

      result.should.equal(false);
      elapsed.should.be.below(500);
    });
  });

  // re2 is not a dependency of this package, so the suite above is skipped in CI.
  // These tests cover the same attack vector with a pure JS stand-in for a
  // non-backtracking engine, so the exploit stays covered without the addon.
  describe('with a non-backtracking engine', function() {
    var enginePatterns, refusals;

    // the shapes that allow catastrophic backtracking: a quantified group that
    // itself contains a quantifier or an alternation
    function hasNestedQuantifier(pattern) {
      for (var i=1; i<pattern.length; i++) {
        var c = pattern.charAt(i);
        if ((c == '*' || c == '+') && pattern.charAt(i-1) == ')') {
          var group = pattern.slice(0, i-1);
          if (group.indexOf('*') >= 0 || group.indexOf('+') >= 0 || group.indexOf('|') >= 0)
            return true;
        }
      }
      return false;
    }

    function refuse() {
      refusals++;
      return false;
    }

    // stands in for RE2: refuses to run patterns it cannot match in linear time,
    // delegates everything else to the native engine
    function safeRegExp(pattern) {
      enginePatterns.push(pattern);
      if (hasNestedQuantifier(pattern))
        return {test: refuse};
      return new RegExp(pattern);
    }

    function dataPatternSchema() {
      return {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
    }

    beforeEach(function() {
      enginePatterns = [];
      refusals = 0;
    });

    it('should run the CVE attack payload through the configured engine', function() {
      var ajv = new Ajv({$data: true, regExp: safeRegExp});
      var validate = ajv.compile(dataPatternSchema());

      // the exact CVE payload: 30 "a"s that can never complete the match, so the
      // native engine explores 2^30 paths and blocks the event loop for ~44s
      var start = Date.now();
      var result = validate({
        pattern: '^(a|a)*$',
        value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + 'X'
      });
      var elapsed = Date.now() - start;

      result.should.equal(false);
      elapsed.should.be.below(500);
      // the attacker controlled pattern never reached "new RegExp"
      enginePatterns.should.contain('^(a|a)*$');
      refusals.should.equal(1);
    });

    it('should run every known ReDoS pattern through the configured engine', function() {
      var ajv = new Ajv({$data: true, regExp: safeRegExp});
      var validate = ajv.compile(dataPatternSchema());

      var redosPatterns = [
        '^(a+)+$',
        '^(a|a)*$',
        '^(a|ab)*$',
        '(x+x+)+y',
        '(a*)*b'
      ];

      redosPatterns.forEach(function(pattern) {
        var start = Date.now();
        var result = validate({
          pattern: pattern,
          value: 'aaaaaaaaaaaaaaaaaaaaaaaaa' + 'X'
        });
        var elapsed = Date.now() - start;

        elapsed.should.be.below(500, 'Pattern ' + pattern + ' took too long: ' + elapsed + 'ms');
        result.should.equal(false);
        enginePatterns.should.contain(pattern);
      });

      refusals.should.equal(redosPatterns.length);
    });

    it('should still validate legitimate $data patterns through the engine', function() {
      var ajv = new Ajv({$data: true, regExp: safeRegExp});
      var validate = ajv.compile(dataPatternSchema());

      validate({pattern: '^[a-z]+$', value: 'abc'}).should.equal(true);
      validate({pattern: '^[a-z]+$', value: 'ABC'}).should.equal(false);
      validate({pattern: '^\\d{3}-\\d{4}$', value: '123-4567'}).should.equal(true);
      validate({pattern: '^\\d{3}-\\d{4}$', value: '12-345'}).should.equal(false);
      enginePatterns.should.contain('^[a-z]+$');
      refusals.should.equal(0);
    });

    it('should not throw when the engine cannot compile the $data pattern', function() {
      var ajv = new Ajv({$data: true, regExp: safeRegExp});
      var validate = ajv.compile(dataPatternSchema());

      // the stand-in delegates this one, so RegExp throws SyntaxError inside the engine
      validate({pattern: '[invalid', value: 'test'}).should.equal(false);
    });

    it('should route static patterns and patternProperties to the engine', function() {
      var ajv = new Ajv({regExp: safeRegExp});
      var validate = ajv.compile({
        type: 'object',
        properties: {
          id: {type: 'string', pattern: '^[a-z]+$'}
        },
        patternProperties: {
          '^x-[0-9]+$': {type: 'number'}
        }
      });

      enginePatterns.should.contain('^[a-z]+$');
      enginePatterns.should.contain('^x-[0-9]+$');
      validate({id: 'abc', 'x-1': 5}).should.equal(true);
      validate({id: 'ABC'}).should.equal(false);
      validate({'x-1': 'not a number'}).should.equal(false);
    });
  });

  describe('with default engine', function() {
    it('should handle invalid regex in $data gracefully', function() {
      var ajv = new Ajv({$data: true});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      // Invalid regex should fail validation, not throw
      var result = validate({pattern: '[invalid', value: 'test'});
      result.should.equal(false);
    });

    it('should handle $data pattern validation correctly', function() {
      var ajv = new Ajv({$data: true});
      var schema = {
        type: 'object',
        properties: {
          pattern: {type: 'string'},
          value: {type: 'string', pattern: {$data: '1/pattern'}}
        }
      };
      var validate = ajv.compile(schema);

      validate({pattern: '^[a-z]+$', value: 'abc'}).should.equal(true);
      validate({pattern: '^[a-z]+$', value: 'ABC'}).should.equal(false);
    });
  });
});
