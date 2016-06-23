/*! aXe v1.1.1
 * Copyright (c) 2016 Deque Systems, Inc.
 *
 * Your use of this Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This entire copyright notice must appear in every copy of this file you
 * distribute or in any file that contains substantial portions of this source
 * code.
 */
(function (window, document) {

/*exported axe, require, define, commons */
// exported namespace for aXe
var axe = {};

// local namespace for common functions
var commons;

/*global matchesSelector, escapeSelector, clone */
/*exported utils */
var utils = axe.utils = {};

utils.matchesSelector = matchesSelector;
utils.escapeSelector = escapeSelector;
utils.clone = clone;

/*exported helpers */
var helpers = {};

/*global Rule, Tool, Check, injectStyle, commons: true */

function setDefaultConfiguration(audit) {
	'use strict';

	var config = audit || {};
	config.rules = config.rules || [];
	config.tools = config.tools || [];
	config.checks = config.checks || [];
	config.data = config.data || {
		checks: {},
		rules: {}
	};

	return config;
}

function unpackToObject(collection, audit, method) {
	'use strict';

	var i, l;
	for (i = 0, l = collection.length; i < l; i++) {
		audit[method](collection[i]);
	}
}

/**
 * Constructor which holds configured rules and information about the document under test
 */
function Audit(audit) {
	'use strict';
	audit = setDefaultConfiguration(audit);

	axe.commons = commons = audit.commons;

	this.reporter = audit.reporter;
	this.rules = [];
	this.tools = {};
	this.checks = {};

	unpackToObject(audit.rules, this, 'addRule');
	unpackToObject(audit.tools, this, 'addTool');
	unpackToObject(audit.checks, this, 'addCheck');
	this.data = audit.data || {
		checks: {},
		rules: {}
	};

	injectStyle(audit.style);
}

/**
 * Adds a new rule to the Audit.  If a rule with specified ID already exists, it will be overridden
 * @param {Object} spec Rule specification object
 */
Audit.prototype.addRule = function (spec) {
	'use strict';

	if (spec.metadata) {
		this.data.rules[spec.id] = spec.metadata;
	}

	var candidate;
	for (var i = 0, l = this.rules.length; i < l; i++) {
		candidate = this.rules[i];
		if (candidate.id === spec.id) {
			this.rules[i] = new Rule(spec, this);
			return;
		}
	}

	this.rules.push(new Rule(spec, this));
};

/**
 * Adds a new tool to the Audit.  If a tool with specified ID already exists, it will be overridden
 * @param {Object} spec Tool specification object
 */
Audit.prototype.addTool = function (spec) {
	'use strict';
	this.tools[spec.id] = new Tool(spec);
};

/**
 * Adds a new check to the Audit.  If a Check with specified ID already exists, it will be overridden
 * @param {Object} spec Check specification object
 */
Audit.prototype.addCheck = function (spec) {
	'use strict';

	if (spec.metadata) {
		this.data.checks[spec.id] = spec.metadata;
	}

	this.checks[spec.id] = new Check(spec);
};

/**
 * Runs the Audit; which in turn should call `run` on each rule.
 * @async
 * @param  {Context}   context The scope definition/context for analysis (include/exclude)
 * @param  {Object}    options Options object to pass into rules and/or disable rules or checks
 * @param  {Function} fn       Callback function to fire when audit is complete
 */
Audit.prototype.run = function (context, options, fn) {
	'use strict';

	var q = utils.queue();
	this.rules.forEach(function (rule) {
		if (utils.ruleShouldRun(rule, context, options)) {
			q.defer(function (cb) {
				rule.run(context, options, cb);
			});
		}
	});
	q.then(fn);
};

/**
 * Runs Rule `after` post processing functions
 * @param  {Array} results  Array of RuleResults to postprocess
 * @param  {Mixed} options  Options object to pass into rules and/or disable rules or checks
 */
Audit.prototype.after = function (results, options) {
	'use strict';

	var rules = this.rules;

	return results.map(function (ruleResult) {
		var rule = utils.findBy(rules, 'id', ruleResult.id);

		return rule.after(ruleResult, options);
	});
};

/*exported CheckResult */

/**
 * Constructor for the result of checks
 * @param {Check} check
 */
function CheckResult(check) {
	'use strict';

	/**
	 * ID of the check.  Unique in the context of a rule.
	 * @type {String}
	 */
	this.id = check.id;

	/**
	 * Any data passed by Check (by calling `this.data()`)
	 * @type {Mixed}
	 */
	this.data = null;

	/**
	 * Any node that is related to the Check, specified by calling `this.relatedNodes([HTMLElement...])` inside the Check
	 * @type {Array}
	 */
	this.relatedNodes = [];

	/**
	 * The return value of the Check's evaluate function
	 * @type {Mixed}
	 */
	this.result = null;
}

/*global CheckResult */

function Check(spec) {
	'use strict';

	/**
	 * Unique ID for the check.  Checks may be re-used, so there may be additional instances of checks
	 * with the same ID.
	 * @type {String}
	 */
	this.id = spec.id;

	/**
	 * Free-form options that are passed as the second parameter to the `evaluate`
	 * @type {Mixed}
	 */
	this.options = spec.options;

	/**
	 * Optional. If specified, only nodes that match this CSS selector are tested
	 * @type {String}
	 */
	this.selector = spec.selector;

	/**
	 * The actual code, accepts 2 parameters: node (the node under test), options (see this.options).
	 * This function is run in the context of a checkHelper, which has the following methods
	 * - `async()` - if called, the check is considered to be asynchronous; returns a callback function
	 * - `data()` - free-form data object, associated to the `CheckResult` which is specific to each node
	 * @type {Function}
	 */
	this.evaluate = spec.evaluate;

	/**
	 * Optional. Filter and/or modify checks for all nodes
	 * @type {Function}
	 */
	if (spec.after) {
		this.after = spec.after;
	}

	if (spec.matches) {
		/**
		 * Optional function to test if check should be run against a node, overrides Check#matches
		 * @type {Function}
		 */
		this.matches = spec.matches;
	}

	/**
	 * enabled by default, if false, this check will not be included in the rule's evaluation
	 * @type {Boolean}
	 */
	this.enabled = spec.hasOwnProperty('enabled') ? spec.enabled : true;
}

/**
 * Determines whether the check should be run against a node
 * @param  {HTMLElement} node The node to test
 * @return {Boolean}      Whether the check should be run
 */
Check.prototype.matches = function (node) {
	'use strict';

	if (!this.selector || utils.matchesSelector(node, this.selector)) {
		return true;
	}

	return false;
};

/**
 * Run the check's evaluate function (call `this.evaluate(node, options)`)
 * @param  {HTMLElement} node  The node to test
 * @param  {Object} options    The options that override the defaults and provide additional
 *                             information for the check
 * @param  {Function} callback Function to fire when check is complete
 */
Check.prototype.run = function (node, options, callback) {
	'use strict';
	options = options || {};
	var enabled = options.hasOwnProperty('enabled') ? options.enabled : this.enabled,
		checkOptions = options.options || this.options;

	if (enabled && this.matches(node)) {
		var checkResult = new CheckResult(this);
		var checkHelper = utils.checkHelper(checkResult, callback);
		var result;

		try {
			result = this.evaluate.call(checkHelper, node, checkOptions);
		} catch (e) {
			axe.log(e.message, e.stack);
			callback(null);
			return;
		}

		if (!checkHelper.isAsync) {
			checkResult.result = result;
			setTimeout(function () {
				callback(checkResult);
			}, 0);
		}
	} else {
		callback(null);
	}
};

/*exported Context */
/*global isNodeInContext */
/**
 * Pushes a unique frame onto `frames` array, filtering any hidden iframes
 * @private
 * @param  {Context} context The context object to operate on and assign to
 * @param  {HTMLElement} frame   The frame to push onto Context
 */
function pushUniqueFrame(collection, frame) {
	'use strict';
	if (utils.isHidden(frame)) {
		return;
	}

	var fr = utils.findBy(collection, 'node', frame);

	if (!fr) {
		collection.push({
			node: frame,
			include: [],
			exclude: []
		});
	}

}

/**
 * Unshift selectors of matching iframes
 * @private
 * @param  {Context} context The context object to operate on and assign to
 * @param  {String} type          The "type" of context, 'include' or 'exclude'
 * @param  {Array} selectorArray  Array of CSS selectors, each element represents a frame;
 * where the last element is the actual node
 */
function pushUniqueFrameSelector(context, type, selectorArray) {
	'use strict';

	context.frames = context.frames || [];

	var result, frame;
	var frames = document.querySelectorAll(selectorArray.shift());

	frameloop:
	for (var i = 0, l = frames.length; i < l; i++) {
		frame = frames[i];
		for (var j = 0, l2 = context.frames.length; j < l2; j++) {
			if (context.frames[j].node === frame) {
				context.frames[j][type].push(selectorArray);
				break frameloop;
			}
		}
		result = {
			node: frame,
			include: [],
			exclude: []
		};

		if (selectorArray) {
			result[type].push(selectorArray);
		}

		context.frames.push(result);
	}
}

/**
 * Normalize the input of "context" so that many different methods of input are accepted
 * @private
 * @param  {Mixed} context  The configuration object passed to `Context`
 * @return {Object}         Normalized context spec to include both `include` and `exclude` arrays
 */
function normalizeContext(context) {
	'use strict';

	// typeof NodeList.length in PhantomJS === function
	if (context && typeof context === 'object' || context instanceof NodeList) {

		if (context instanceof Node) {
			return {
				include: [context],
				exclude: []
			};
		}

		if (context.hasOwnProperty('include') || context.hasOwnProperty('exclude')) {
			return {
				include: context.include || [document],
				exclude: context.exclude || []
			};
		}

		if (context.length === +context.length) {
			return {
				include: context,
				exclude: []
			};
		}
	}

	if (typeof context === 'string') {
		return {
			include: [context],
			exclude: []
		};
	}

	return {
		include: [document],
		exclude: []
	};
}

/**
 * Finds frames in context, converts selectors to Element references and pushes unique frames
 * @private
 * @param  {Context} context The instance of Context to operate on
 * @param  {String} type     The "type" of thing to parse, "include" or "exclude"
 * @return {Array}           Parsed array of matching elements
 */
function parseSelectorArray(context, type) {
	'use strict';

	var item,
		result = [];
	for (var i = 0, l = context[type].length; i < l; i++) {
		item = context[type][i];
		// selector
		if (typeof item === 'string') {
			result = result.concat(utils.toArray(document.querySelectorAll(item)));
			break;
		} else if (item && item.length) {

			if (item.length > 1) {
				pushUniqueFrameSelector(context, type, item);
			} else {
				result = result.concat(utils.toArray(document.querySelectorAll(item[0])));
			}
		} else {
			result.push(item);
		}
	}

	// filter nulls
	return result.filter(function (r) {
		return r;
	});
}

/**
 * Holds context of includes, excludes and frames for analysis.
 *
 * @todo  clarify and sync changes to design doc
 * Context : {IncludeStrings} || {
 *   // defaults to document/all
 *   include: {IncludeStrings},
 *   exclude : {ExcludeStrings}
 * }
 *
 * IncludeStrings : [{CSSSelectorArray}] || Node
 * ExcludeStrings : [{CSSSelectorArray}]
 * `CSSSelectorArray` an Array of selector strings that addresses a Node in a multi-frame document. All addresses
 * are in this form regardless of whether the document contains any frames.To evaluate the selectors to
 * find the node referenced by the array, evaluate the selectors in-order, starting in window.top. If N
 * is the length of the array, then the first N-1 selectors should result in an iframe and the last
 * selector should result in the specific node.
 *
 * @param {Object} spec Configuration or "specification" object
 */
function Context(spec) {
	'use strict';
	var self = this;

	this.frames = [];
	this.initiator = (spec && typeof spec.initiator === 'boolean') ? spec.initiator : true;
	this.page = false;

	spec = normalizeContext(spec);
	this.exclude = spec.exclude;
	this.include = spec.include;

	this.include = parseSelectorArray(this, 'include');
	this.exclude = parseSelectorArray(this, 'exclude');

	utils.select('frame, iframe', this).forEach(function (frame) {
		if (isNodeInContext(frame, self)) {
			pushUniqueFrame(self.frames, frame);
		}
	});

	if (this.include.length === 1 && this.include[0] === document) {
		this.page = true;
	}

}

/*exported RuleResult */

/**
 * Constructor for the result of Rules
 * @param {Rule} rule
 */
function RuleResult(rule) {
	'use strict';

	/**
	 * The ID of the Rule whom this result belongs to
	 * @type {String}
	 */
	this.id = rule.id;

	/**
	 * The calculated result of the Rule, either PASS, FAIL or NA
	 * @type {String}
	 */
	this.result = axe.constants.result.NA;

	/**
	 * Whether the Rule is a "pageLevel" rule
	 * @type {Boolean}
	 */
	this.pageLevel = rule.pageLevel;

	/**
	 * Impact of the violation
	 * @type {String}  Plain-english impact or null if rule passes
	 */
	this.impact = null;

	/**
	 * Holds information regarding nodes and individual CheckResults
	 * @type {Array}
	 */
	this.nodes = [];
}

/*global RuleResult */

function Rule(spec, parentAudit) {
	'use strict';

	this._audit = parentAudit;

	/**
	 * The code, or string ID of the rule
	 * @type {String}
	 */
	this.id = spec.id;

	/**
	 * Selector that this rule applies to
	 * @type {String}
	 */
	this.selector = spec.selector || '*';

	/**
	 * Whether to exclude hiddden elements form analysis.  Defaults to true.
	 * @type {Boolean}
	 */
	this.excludeHidden = typeof spec.excludeHidden === 'boolean' ? spec.excludeHidden : true;

	/**
	 * Flag to enable or disable rule
	 * @type {Boolean}
	 */
	this.enabled = typeof spec.enabled === 'boolean' ? spec.enabled : true;

	/**
	 * Denotes if the rule should be run if Context is not an entire page AND whether
	 * the Rule should be satisified regardless of Node
	 * @type {Boolean}
	 */
	this.pageLevel = typeof spec.pageLevel === 'boolean' ? spec.pageLevel : false;

	/**
	 * Checks that any may return true to satisfy rule
	 * @type {Array}
	 */
	this.any = spec.any || [];

	/**
	 * Checks that must all return true to satisfy rule
	 * @type {Array}
	 */
	this.all = spec.all || [];

	/**
	 * Checks that none may return true to satisfy rule
	 * @type {Array}
	 */
	this.none = spec.none || [];

	/**
	 * Tags associated to this rule
	 * @type {Array}
	 */
	this.tags = spec.tags || [];

	if (spec.matches) {
		/**
		 * Optional function to test if rule should be run against a node, overrides Rule#matches
		 * @type {Function}
		 */
		this.matches = spec.matches;
	}

}

/**
 * Optionally test each node against a `matches` function to determine if the rule should run against
 * a given node.  Defaults to `true`.
 * @return {Boolean}    Whether the rule should run
 */
Rule.prototype.matches = function () {
	'use strict';

	return true;
};

/**
 * Selects `HTMLElement`s based on configured selector
 * @param  {Context} context The resolved Context object
 * @return {Array}           All matching `HTMLElement`s
 */
Rule.prototype.gather = function (context) {
	'use strict';
	var elements = utils.select(this.selector, context);
	if (this.excludeHidden) {
		return elements.filter(function (element) {
			return !utils.isHidden(element);
		});
	}
	return elements;
};

Rule.prototype.runChecks = function (type, node, options, callback) {
	'use strict';

	var self = this;
	var checkQueue = utils.queue();
	this[type].forEach(function (c) {
		var check = self._audit.checks[c.id || c];
		var option = utils.getCheckOption(check, self.id, options);
		checkQueue.defer(function (done) {
			check.run(node, option, done);
		});
	});

	checkQueue.then(function (results) {
		results = results.filter(function (check) {
			return check;
		});
		callback({ type: type, results: results });
	});

};

/**
 * Runs the Rule's `evaluate` function
 * @param  {Context}   context  The resolved Context object
 * @param  {Mixed}   options  Options specific to this rule
 * @param  {Function} callback Function to call when evaluate is complete; receives a RuleResult instance
 */
Rule.prototype.run = function (context, options, callback) {
	'use strict';

	var nodes = this.gather(context);
	var q = utils.queue();
	var self = this;
	var ruleResult;

	ruleResult = new RuleResult(this);
	nodes.forEach(function (node) {
		if (self.matches(node)) {
			q.defer(function (nodeQueue) {
				var checkQueue = utils.queue();
				checkQueue.defer(function (done) {
					self.runChecks('any', node, options, done);
				});
				checkQueue.defer(function (done) {
					self.runChecks('all', node, options, done);
				});
				checkQueue.defer(function (done) {
					self.runChecks('none', node, options, done);
				});

				checkQueue.then(function (results) {
					if (results.length) {
						var hasResults = false,
							result = {
								node: new utils.DqElement(node)
							};
						results.forEach(function (r) {
							var res = r.results.filter(function (result) {
								return result;
							});
							result[r.type] = res;
							if (res.length) {
								hasResults = true;
							}
						});
						if (hasResults) {
							ruleResult.nodes.push(result);
						}
					}
					nodeQueue();
				});

			});
		}
	});

	q.then(function () {
		callback(ruleResult);
	});

};

/**
 * Iterates the rule's Checks looking for ones that have an after function
 * @private
 * @param  {Rule} rule The rule to check for after checks
 * @return {Array}      Checks that have an after function
 */
function findAfterChecks(rule) {
	'use strict';

	return utils.getAllChecks(rule).map(function (c) {
		var check = rule._audit.checks[c.id || c];
		return typeof check.after === 'function' ? check : null;
	}).filter(Boolean);
}

/**
 * Finds and collates all results for a given Check on a specific Rule
 * @private
 * @param  {Array} nodes RuleResult#nodes; array of 'detail' objects
 * @param  {String} checkID The ID of the Check to find
 * @return {Array}         Matching CheckResults
 */
function findCheckResults(nodes, checkID) {
	'use strict';

	var checkResults = [];
	nodes.forEach(function (nodeResult) {
		var checks = utils.getAllChecks(nodeResult);
		checks.forEach(function (checkResult) {
			if (checkResult.id === checkID) {
				checkResults.push(checkResult);
			}
		});
	});
	return checkResults;
}

function filterChecks(checks) {
	'use strict';

	return checks.filter(function (check) {
		return check.filtered !== true;
	});
}

function sanitizeNodes(result) {
	'use strict';
	var checkTypes = ['any', 'all', 'none'];

	var nodes = result.nodes.filter(function (detail) {
		var length = 0;
		checkTypes.forEach(function (type) {
			detail[type] = filterChecks(detail[type]);
			length += detail[type].length;
		});
		return length > 0;
	});

	if (result.pageLevel && nodes.length) {
		nodes = [nodes.reduce(function (a, b) {
			if (a) {
				checkTypes.forEach(function (type) {
					a[type].push.apply(a[type], b[type]);
				});
				return a;
			}
		})];
	}
	return nodes;
}

/**
 * Runs all of the Rule's Check#after methods
 * @param  {RuleResult} result  The "pre-after" RuleResult
 * @param  {Mixed} options Options specific to the rule
 * @return {RuleResult}         The RuleResult as filtered by after functions
 */
Rule.prototype.after = function (result, options) {
	'use strict';

	var afterChecks = findAfterChecks(this);
	var ruleID = this.id;
	afterChecks.forEach(function (check) {
		var beforeResults = findCheckResults(result.nodes, check.id);
		var option = utils.getCheckOption(check, ruleID, options);

		var afterResults = check.after(beforeResults, option);
		beforeResults.forEach(function (item) {
			if (afterResults.indexOf(item) === -1) {
				item.filtered = true;
			}
		});
	});

	result.nodes = sanitizeNodes(result);
	return result;
};

/*exported Tool */

function Tool(spec) {
  'use strict';
  spec.source = spec.source || {};

  this.id = spec.id;
  this.options = spec.options;
  this._run = spec.source.run;
  this._cleanup = spec.source.cleanup;

  this.active = false;
}

Tool.prototype.run = function (element, options, callback) {
  'use strict';
  options = typeof options === 'undefined' ? this.options : options;

  this.active = true;
  this._run(element, options, callback);
};

Tool.prototype.cleanup = function (callback) {
  'use strict';

  this.active = false;
  this._cleanup(callback);
};


axe.constants = {};

axe.constants.result = {
	PASS: 'PASS',
	FAIL: 'FAIL',
	NA: 'NA'
};

axe.constants.raisedMetadata = {
	impact: ['minor', 'moderate', 'serious', 'critical']
};

/*global axe */
axe.version = 'dev';

/*jshint devel: true */

/**
 * Logs a message to the developer console (if it exists and is active).
 */
axe.log = function () {
	'use strict';
	if (typeof console === 'object' && console.log) {
		// IE does not support console.log.apply
		Function.prototype.apply.call(console.log, console, arguments);
	}
};

function cleanupTools(callback) {
  'use strict';

  if (!axe._audit) {
    throw new Error('No audit configured');
  }

  var q = utils.queue();

  Object.keys(axe._audit.tools).forEach(function (key) {
    var tool = axe._audit.tools[key];
    if (tool.active) {
      q.defer(function (done) {
        tool.cleanup(done);
      });
    }
  });

  utils.toArray(document.querySelectorAll('frame, iframe')).forEach(function (frame) {
    q.defer(function (done) {
      return utils.sendCommandToFrame(frame, {
        command: 'cleanup-tool'
      }, done);
    });
  });

  q.then(callback);
}
axe.cleanup = cleanupTools;

/*global reporters */
axe.configure = function (spec) {
	'use strict';

	var audit = axe._audit;
	if (!audit) {
		throw new Error('No audit configured');
	}

	if (spec.reporter && (typeof spec.reporter === 'function' || reporters[spec.reporter])) {
		audit.reporter = spec.reporter;
	}

	if (spec.checks) {
		spec.checks.forEach(function (check) {
			audit.addCheck(check);
		});
	}

	if (spec.rules) {
		spec.rules.forEach(function (rule) {
			audit.addRule(rule);
		});
	}

	if (spec.tools) {
		spec.tools.forEach(function (tool) {
			audit.addTool(tool);
		});
	}

};

/**
 * Searches and returns rules that contain a tag in the list of tags.
 * @param  {Array}   tags  Optional array of tags
 * @return {Array}  Array of rules
 */
axe.getRules = function(tags) {
	'use strict';

	tags = tags || [];
	var matchingRules = !tags.length ? axe._audit.rules : axe._audit.rules.filter(function(item) {
		return !!tags.filter(function(tag) {
			return item.tags.indexOf(tag) !== -1;
		}).length;
	});

	var ruleData = axe._audit.data.rules || {};
	return matchingRules.map(function(matchingRule) {
		var rd = ruleData[matchingRule.id] || {};
		return {
			ruleId: matchingRule.id,
			description: rd.description,
			help: rd.help,
			helpUrl: rd.helpUrl,
			tags: matchingRule.tags,
		};
	});
};

/*global Audit, runRules, runTool, cleanupTools */
function runCommand(data, callback) {
	'use strict';

	var context = (data && data.context) || {};
	if (context.include && !context.include.length) {
		context.include = [document];
	}
	var options = (data && data.options) || {};

	switch(data.command) {
		case 'rules':
			return runRules(context, options, callback);
		case 'run-tool':
			return runTool(data.parameter, data.selectorArray, options, callback);
		case 'cleanup-tool':
			return cleanupTools(callback);
	}
}

/**
 * Sets up Rules, Messages and default options for Checks, must be invoked before attempting analysis
 * @param  {Object} audit The "audit specifcation" object
 * @private
 */
axe._load = function (audit) {
	'use strict';

	utils.respondable.subscribe('axe.ping', function (data, respond) {
		respond({axe: true});
	});

	utils.respondable.subscribe('axe.start', runCommand);

	axe._audit = new Audit(audit);
};

/*exported getReporter */
var reporters = {};
var defaultReporter;

function getReporter(reporter) {
	'use strict';

	if (typeof reporter === 'string' && reporters[reporter]) {
		return reporters[reporter];
	}

	if (typeof reporter === 'function') {
		return reporter;
	}

	return defaultReporter;
}

axe.reporter = function registerReporter(name, cb, isDefault) {
	'use strict';

	reporters[name] = cb;
	if (isDefault) {
		defaultReporter = cb;
	}
};

/*global Context, getReporter */
/*exported runRules */

/**
 * Starts analysis on the current document and its subframes
 * @private
 * @param  {Object}   context  The `Context` specification object @see Context
 * @param  {Array}    options  Optional RuleOptions
 * @param  {Function} callback The function to invoke when analysis is complete; receives an array of `RuleResult`s
 */
function runRules(context, options, callback) {
	'use strict';
	context = new Context(context);

	var q = utils.queue();
	var audit = axe._audit;

	if (context.frames.length) {
		q.defer(function (done) {
			utils.collectResultsFromFrames(context, options, 'rules', null, done);
		});
	}
	q.defer(function (cb) {
		audit.run(context, options, cb);
	});
	q.then(function (data) {
		// Add wrapper object so that we may use the same "merge" function for results from inside and outside frames
		var results = utils.mergeResults(data.map(function (d) {
			return {
				results: d
			};
		}));

		// after should only run once, so ensure we are in the top level window
		if (context.initiator) {
			results = audit.after(results, options);
			results = results.map(utils.finalizeRuleResult);
		}

		callback(results);
	});
}

axe.a11yCheck = function (context, options, callback) {
	'use strict';
	if (typeof options === 'function') {
		callback = options;
		options = {};
	}

	if (!options || typeof options !== 'object') {
		options = {};
	}

	var audit = axe._audit;
	if (!audit) {
		throw new Error('No audit configured');
	}
	var reporter = getReporter(options.reporter || audit.reporter);
	runRules(context, options, function (results) {
		reporter(results, callback);
	});
};

/*exported runTool, cleanupTools */

function runTool(toolId, selectorArray, options, callback) {
  'use strict';

  if (!axe._audit) {
    throw new Error('No audit configured');
  }

  if (selectorArray.length > 1) {
    var frame = document.querySelector(selectorArray.shift());
    return utils.sendCommandToFrame(frame, {
      options: options,
      command: 'run-tool',
      parameter: toolId,
      selectorArray: selectorArray
    }, callback);
  }

  var node = document.querySelector(selectorArray.shift());
  axe._audit.tools[toolId].run(node, options, callback);
}
axe.tool = runTool;

/*global helpers */

/**
 * Finds failing Checks and combines each help message into an array
 * @param  {Object} nodeData Individual "detail" object to generate help messages for
 * @return {String}          failure messages
 */
helpers.failureSummary = function failureSummary(nodeData) {
	'use strict';

	var failingChecks = {};
	// combine "all" and "none" as messaging is the same
	failingChecks.none = nodeData.none.concat(nodeData.all);
	failingChecks.any = nodeData.any;

	return Object.keys(failingChecks).map(function (key) {
		if (!failingChecks[key].length) {
			return;
		}
		// @todo rm .failureMessage
		return axe._audit.data.failureSummaries[key].failureMessage(failingChecks[key].map(function (check) {
			return check.message || '';
		}));
	}).filter(function (i) {
		return i !== undefined;
	}).join('\n\n');
};

/*global helpers */

helpers.formatCheck = function (check) {
	'use strict';
	
	return {
		id: check.id,
		impact: check.impact,
		message: check.message,
		data: check.data,
		relatedNodes: check.relatedNodes.map(helpers.formatNode)
	};
};

/*global helpers */
helpers.formatChecks = function (nodeResult, data) {
	'use strict';

	nodeResult.any = data.any.map(helpers.formatCheck);
	nodeResult.all = data.all.map(helpers.formatCheck);
	nodeResult.none = data.none.map(helpers.formatCheck);
	return nodeResult;
};

/*global helpers */
helpers.formatNode = function (node) {
	'use strict';

	return {
		target: node ? node.selector : null,
		html: node ? node.source : null
	};
};

/*global helpers */

helpers.formatRuleResult = function (ruleResult) {
	'use strict';
	
	return {
		id: ruleResult.id,
		description: ruleResult.description,
		help: ruleResult.help,
		helpUrl: ruleResult.helpUrl || null,
		impact: null,
		tags: ruleResult.tags,
		nodes: []
	};
};

/*global helpers */
helpers.splitResultsWithChecks = function (results) {
	'use strict';
	return helpers.splitResults(results, helpers.formatChecks);
};

/*global helpers */

helpers.splitResults = function (results, nodeDataMapper) {
	'use strict';

	var violations = [],
		passes = [];

	results.forEach(function (rr) {

		function mapNode(nodeData) {
			var result = nodeData.result || rr.result;
			var node = helpers.formatNode(nodeData.node);
			node.impact = nodeData.impact || null;

			return nodeDataMapper(node, nodeData, result);
		}

		var failResult,
			passResult = helpers.formatRuleResult(rr);

		failResult = utils.clone(passResult);
		failResult.impact = rr.impact || null;

		failResult.nodes = rr.violations.map(mapNode);
		passResult.nodes = rr.passes.map(mapNode);

		if (failResult.nodes.length) {
			violations.push(failResult);
		}
		if (passResult.nodes.length) {
			passes.push(passResult);
		}
	});

	return {
		violations: violations,
		passes: passes,
		url: window.location.href,
		timestamp: new Date()
	};
};

/*global helpers */
axe.reporter('na', function (results, callback) {
	'use strict';
	var na = results.filter(function (rr) {
		return rr.violations.length === 0 && rr.passes.length === 0;
	}).map(helpers.formatRuleResult);

	var formattedResults = helpers.splitResultsWithChecks(results);
	callback({
		violations: formattedResults.violations,
		passes: formattedResults.passes,
		notApplicable: na,
		timestamp: formattedResults.timestamp,
		url: formattedResults.url
	});
});

/*global helpers */
axe.reporter('no-passes', function (results, callback) {
	'use strict';

	var formattedResults = helpers.splitResultsWithChecks(results);
	callback({
		violations: formattedResults.violations,
		timestamp: formattedResults.timestamp,
		url: formattedResults.url
	});
});

axe.reporter('raw', function (results, callback) {
	'use strict';
	callback(results);
});

/*global helpers */

axe.reporter('v1', function (results, callback) {
	'use strict';
	var formattedResults = helpers.splitResults(results, function (nodeResult, data, result) {
		if (result === axe.constants.result.FAIL) {
			nodeResult.failureSummary = helpers.failureSummary(data);
		}

		return nodeResult;
	});
	callback({
		violations: formattedResults.violations,
		passes: formattedResults.passes,
		timestamp: formattedResults.timestamp,
		url: formattedResults.url
	});
});

/*global helpers */


axe.reporter('v2', function (results, callback) {
	'use strict';
	var formattedResults = helpers.splitResultsWithChecks(results);
	callback({
		violations: formattedResults.violations,
		passes: formattedResults.passes,
		timestamp: formattedResults.timestamp,
		url: formattedResults.url
	});
}, true);

/**
 * Helper to denote which checks are asyncronous and provide callbacks and pass data back to the CheckResult
 * @param  {CheckResult}   checkResult The target object
 * @param  {Function} callback    The callback to expose when `this.async()` is called
 * @return {Object}               Bound to `this` for a check's fn
 */
utils.checkHelper = function checkHelper(checkResult, callback) {
	'use strict';

	return {
		isAsync: false,
		async: function () {
			this.isAsync = true;
			return function (result) {
				checkResult.value = result;
				callback(checkResult);
			};
		},
		data: function (data) {
			checkResult.data = data;
		},
		relatedNodes: function (nodes) {
			nodes = nodes instanceof Node ? [nodes] : utils.toArray(nodes);
			checkResult.relatedNodes = nodes.map(function (element) {
				return new utils.DqElement(element);
			});
		}
	};
};


/**
 * Sends a command to the sepecified frame
 * @param  {Element}  node       The frame element to send the message to
 * @param  {Object}   parameters Parameters to pass to the frame
 * @param  {Function} callback   Function to call when results from all frames have returned
 */
utils.sendCommandToFrame = function(node, parameters, callback) {
  'use strict';

  var win = node.contentWindow;
  if (!win) {
    axe.log('Frame does not have a content window', node);
    return callback({});
  }

  var timeout = setTimeout(function () {
    timeout = setTimeout(function () {
      axe.log('No response from frame: ', node);
      callback(null);
    }, 0);
  }, 500);

  utils.respondable(win, 'axe.ping', null, function () {
    clearTimeout(timeout);
    timeout = setTimeout(function () {
      axe.log('Error returning results from frame: ', node);
      callback({});
      callback = null;
    }, 30000);
    utils.respondable(win, 'axe.start', parameters, function (data) {
      if (callback) {
        clearTimeout(timeout);
        callback(data);
      }
    });
  });

};


/**
* Sends a message to frames to start analysis and collate results (via `mergeResults`)
* @private
* @param  {Context}   context  The resolved Context object
* @param  {Object}   options   Options object (as passed to `runRules`)
* @param  {Function} callback  Function to call when results from all frames have returned
*/
utils.collectResultsFromFrames = function collectResultsFromFrames(context, options, command, parameter, callback) {
  'use strict';

  var q = utils.queue();
  var frames = context.frames;

  function defer(frame) {
    var params = {
      options: options,
      command: command,
      parameter: parameter,
      context: {
        initiator: false,
        page: context.page,
        include: frame.include || [],
        exclude: frame.exclude || []
      }
    };

    q.defer(function (done) {
      var node = frame.node;
      utils.sendCommandToFrame(node, params, function (data) {
        if (data) {
          return done({
            results: data,
            frameElement: node,
            frame: utils.getSelector(node)
          });
        }
        done(null);
      });
    });
  }

  for (var i = 0, l = frames.length; i < l; i++) {
    defer(frames[i]);
  }

  q.then(function (data) {
    callback(utils.mergeResults(data));
  });
};


/**
 * Wrapper for Node#contains; PhantomJS does not support Node#contains and erroneously reports that it does
 * @param  {HTMLElement} node      The candidate container node
 * @param  {HTMLElement} otherNode The node to test is contained by `node`
 * @return {Boolean}           Whether `node` contains `otherNode`
 */
utils.contains = function (node, otherNode) {
	//jshint bitwise: false
	'use strict';

	if (typeof node.contains === 'function') {
		return node.contains(otherNode);
	}

	return !!(node.compareDocumentPosition(otherNode) & 16);

};
/*exported DqElement */

function truncate(str, maxLength) {
	'use strict';

	maxLength = maxLength || 300;

	if (str.length > maxLength) {
		var index = str.indexOf('>');
		str = str.substring(0, index + 1);
	}

	return str;
}

function getSource (element) {
	'use strict';

	var source = element.outerHTML;
	if (!source && typeof XMLSerializer === 'function') {
		source = new XMLSerializer().serializeToString(element);
	}
	return truncate(source || '');
}

/**
 * "Serialized" `HTMLElement`. It will calculate the CSS selector,
 * grab the source (outerHTML) and offer an array for storing frame paths
 * @param {HTMLElement} element The element to serialize
 * @param {Object} spec Properties to use in place of the element when instantiated on Elements from other frames
 */
function DqElement(element, spec) {
	'use strict';
	spec = spec || {};

	/**
	 * A unique CSS selector for the element
	 * @type {String}
	 */
	this.selector = spec.selector || [utils.getSelector(element)];

	/**
	 * The generated HTML source code of the element
	 * @type {String}
	 */
	this.source = spec.source !== undefined ? spec.source : getSource(element);

	/**
	 * The element which this object is based off or the containing frame, used for sorting.
	 * Excluded in toJSON method.
	 * @type {HTMLElement}
	 */
	this.element = element;
}

DqElement.prototype.toJSON = function () {
	'use strict';
	return {
		selector: this.selector,
		source: this.source
	};
};

utils.DqElement = DqElement;


/**
 * Extends metadata onto result object and executes any functions.  Will not deeply extend.
 * @param  {Object} to   The target of the extend
 * @param  {Object} from Metadata to extend
 * @param  {Array}  blacklist property names to exclude from resulting object
 */
utils.extendBlacklist = function (to, from, blacklist) {
	'use strict';
	blacklist = blacklist || [];

	for (var i in from) {
		if (from.hasOwnProperty(i) && blacklist.indexOf(i) === -1) {
			to[i] = from[i];
		}
	}

	return to;
};


/**
 * Extends metadata onto result object and executes any functions
 * @param  {Object} to   The target of the extend
 * @param  {Object} from Metadata to extend
 */
utils.extendMetaData = function (to, from) {
	'use strict';

	for (var i in from) {
		if (from.hasOwnProperty(i)) {
			if (typeof from[i] === 'function') {
				try {
					to[i] = from[i](to);
				} catch (e) {
					to[i] = null;
				}
			} else {
				to[i] = from[i];
			}
		}
	}
};


function raiseMetadata(obj, checks) {
	'use strict';

	Object.keys(axe.constants.raisedMetadata).forEach(function (key) {
		var collection = axe.constants.raisedMetadata[key];
		var highestIndex = checks.reduce(function (prevIndex, current) {
		  var currentIndex = collection.indexOf(current[key]);
		  return currentIndex > prevIndex ? currentIndex : prevIndex;
		}, -1);
		if (collection[highestIndex]) {
			obj[key] = collection[highestIndex];
		}
	});

}

/**
 * Calculates the result (PASS or FAIL) of a Node (node-level) or an entire Rule (page-level)
 * @private
 * @param  {Array} checks  Array of checks to calculate the result of
 * @return {String}        Either "PASS" or "FAIL"
 */
function calculateCheckResult(failingChecks) {
	'use strict';
	var isFailing = failingChecks.any.length || failingChecks.all.length || failingChecks.none.length;

	return isFailing ? axe.constants.result.FAIL : axe.constants.result.PASS;
}

/**
 * Iterates and calculates the results of each Node and then rolls the result up to the parent RuleResult
 * @private
 * @param  {RuleResult} ruleResult The RuleResult to test
 */
function calculateRuleResult(ruleResult) {
	'use strict';
	function checkMap(check) {
		return utils.extendBlacklist({}, check, ['result']);
	}


	var newRuleResult = utils.extendBlacklist({
		violations: [],
		passes: []
	}, ruleResult, ['nodes']);

	ruleResult.nodes.forEach(function (detail) {

		var failingChecks = utils.getFailingChecks(detail);
		var result = calculateCheckResult(failingChecks);

		if (result === axe.constants.result.FAIL) {
			raiseMetadata(detail, utils.getAllChecks(failingChecks));
			detail.any = failingChecks.any.map(checkMap);
			detail.all = failingChecks.all.map(checkMap);
			detail.none = failingChecks.none.map(checkMap);
			newRuleResult.violations.push(detail);
			return;
		}

		detail.any = detail.any.filter(function (check) {
			return check.result;
		}).map(checkMap);
		// no need to filter `all` or `none` since we know they all pass
		detail.all = detail.all.map(checkMap);
		detail.none = detail.none.map(checkMap);

		newRuleResult.passes.push(detail);
	});
	raiseMetadata(newRuleResult, newRuleResult.violations);

	newRuleResult.result = newRuleResult.violations.length ? axe.constants.result.FAIL :
		(newRuleResult.passes.length ? axe.constants.result.PASS : newRuleResult.result);

	return newRuleResult;
}

utils.getFailingChecks = function (detail) {
	'use strict';

	var any = detail.any.filter(function (check) {
		return !check.result;
	});
	return {
		all: detail.all.filter(function (check) {
			return !check.result;
		}),
		any: any.length === detail.any.length ? any : [],
		none: detail.none.filter(function (check) {
			return !!check.result;
		})
	};
};


/**
 * Calculates the result of a Rule based on its types and the result of its child Checks
 * @param  {RuleResult} ruleResult The RuleResult to calculate the result of
 */
utils.finalizeRuleResult = function (ruleResult) {
	'use strict';

	utils.publishMetaData(ruleResult);
	return calculateRuleResult(ruleResult);
};


/**
 * Iterates an array of objects looking for a property with a specific value
 * @param  {Array} array  The array of objects to iterate
 * @param  {String} key   The property name to test against
 * @param  {Mixed} value  The value to find
 * @return {Object}       The first matching object or `undefined` if no match
 */
utils.findBy = function (array, key, value) {
	'use strict';
	array = array || [];

	var index, length;
	for (index = 0, length = array.length; index < length; index++) {
		if (array[index][key] === value) {
			return array[index];
		}
	}
};

/**
 * Gets all Checks (or CheckResults) for a given Rule or RuleResult
 * @param {RuleResult|Rule} rule
 */
utils.getAllChecks = function getAllChecks(object) {
	'use strict';
	var result = [];
	return result.concat(object.any || []).concat(object.all || []).concat(object.none || []);
};


/**
 * Determines which CheckOption to use, either defined on the rule options, global check options or the check itself
 * @param  {Check} check    The Check object
 * @param  {String} ruleID  The ID of the rule
 * @param  {Object} options Options object as passed to main API
 * @return {Object}         The resolved object with `options` and `enabled` keys
 */
utils.getCheckOption = function (check, ruleID, options) {
	'use strict';
	var ruleCheckOption = ((options.rules && options.rules[ruleID] || {}).checks || {})[check.id];
	var checkOption = (options.checks || {})[check.id];

	var enabled = check.enabled;
	var opts = check.options;

	if (checkOption) {
		if (checkOption.hasOwnProperty('enabled')) {
			enabled = checkOption.enabled;
		}
		if (checkOption.hasOwnProperty('options')) {
			opts = checkOption.options;
		}

	}

	if (ruleCheckOption) {
		if (ruleCheckOption.hasOwnProperty('enabled')) {
			enabled = ruleCheckOption.enabled;
		}
		if (ruleCheckOption.hasOwnProperty('options')) {
			opts = ruleCheckOption.options;
		}
	}

	return {
		enabled: enabled,
		options: opts
	};
};
/**
 * Gets the index of element siblings that have the same nodeName
 * Intended for use with the CSS psuedo-class `:nth-of-type()` and xpath node index
 * @param  {HTMLElement} element The element to test
 * @return {Number}         The number of preceeding siblings with the same nodeName
 * @private
 */
function nthOfType(element) {
	'use strict';

	var index = 1,
		type = element.nodeName;

	/*jshint boss:true */
	while (element = element.previousElementSibling) {
		if (element.nodeName === type) {
			index++;
		}
	}

	return index;
}

/**
 * Checks if an element has siblings with the same selector
 * @param  {HTMLElement} node     The element to test
 * @param  {String} selector The CSS selector to test
 * @return {Boolean}          Whether any of element's siblings matches selector
 * @private
 */
function siblingsHaveSameSelector(node, selector) {
	'use strict';

	var index, sibling,
		siblings = node.parentNode.children;

	if (!siblings) {
		return false;
	}

	var length = siblings.length;

	for (index = 0; index < length; index++) {
		sibling = siblings[index];
		if (sibling !== node && utils.matchesSelector(sibling, selector)) {
			return true;
		}
	}
	return false;
}


/**
 * Gets a unique CSS selector
 * @param  {HTMLElement} node The element to get the selector for
 * @return {String}      Unique CSS selector for the node
 */
utils.getSelector = function getSelector(node) {
	//jshint maxstatements: 21
	'use strict';

	function escape(p) {
		return utils.escapeSelector(p);
	}

	var parts = [], part;

	while (node.parentNode) {
		part = '';

		if (node.id && document.querySelectorAll('#' + utils.escapeSelector(node.id)).length === 1) {
			parts.unshift('#' + utils.escapeSelector(node.id));
			break;
		}

		if (node.className && typeof node.className === 'string') {
			part = '.' + node.className.trim().split(/\s+/).map(escape).join('.');
			if (part === '.' || siblingsHaveSameSelector(node, part)) {
				part = '';
			}
		}

		if (!part) {
			part = utils.escapeSelector(node.nodeName).toLowerCase();
			if (part === 'html' || part === 'body') {
				parts.unshift(part);
				break;
			}
			if (siblingsHaveSameSelector(node, part)) {
				part += ':nth-of-type(' + nthOfType(node) + ')';
			}

		}

		parts.unshift(part);

		node = node.parentNode;
	}

	return parts.join(' > ');

};

/*exported injectStyle */

var styleSheet;
function injectStyle(style) {
	'use strict';

	if (styleSheet && styleSheet.parentNode) {
		styleSheet.parentNode.removeChild(styleSheet);
		styleSheet = null;
	}
	if (!style) {
		return;
	}

	var head = document.head || document.getElementsByTagName('head')[0];
	styleSheet = document.createElement('style');
	styleSheet.type = 'text/css';

	if (styleSheet.styleSheet === undefined) { // Not old IE
		styleSheet.appendChild(document.createTextNode(style));
	} else {
		styleSheet.styleSheet.cssText = style;
	}

	head.appendChild(styleSheet);

	return styleSheet;
}



/**
 * Determine whether an element is visible
 *
 * @param {HTMLElement} el The HTMLElement
 * @return {Boolean} The element's visibilty status
 */
utils.isHidden = function isHidden(el, recursed) {
	'use strict';

	// 9 === Node.DOCUMENT
	if (el.nodeType === 9) {
		return false;
	}

	var style = window.getComputedStyle(el, null);

	if (!style || (!el.parentNode || (style.getPropertyValue('display') === 'none' ||

			(!recursed &&
				// visibility is only accurate on the first element
				(style.getPropertyValue('visibility') === 'hidden')) ||

			(el.getAttribute('aria-hidden') === 'true')))) {

		return true;
	}

	return utils.isHidden(el.parentNode, true);

};


/**
* Adds the owning frame's CSS selector onto each instance of DqElement
* @private
* @param  {Array} resultSet `nodes` array on a `RuleResult`
* @param  {HTMLElement} frameElement  The frame element
* @param  {String} frameSelector     Unique CSS selector for the frame
*/
function pushFrame(resultSet, frameElement, frameSelector) {
  'use strict';
  resultSet.forEach(function (res) {
    res.node.selector.unshift(frameSelector);
    res.node = new utils.DqElement(frameElement, res.node);
    var checks = utils.getAllChecks(res);
    if (checks.length) {
      checks.forEach(function (check) {
        check.relatedNodes.forEach(function (node) {
          node.selector.unshift(frameSelector);
          node = new utils.DqElement(frameElement, node);
        });
      });
    }
  });
}

/**
* Adds `to` to `from` and then re-sorts by DOM order
* @private
* @param  {Array} target  `nodes` array on a `RuleResult`
* @param  {Array} to   `nodes` array on a `RuleResult`
* @return {Array}      The merged and sorted result
*/
function spliceNodes(target, to) {
  'use strict';

  var firstFromFrame = to[0].node,
  sorterResult, t;
  for (var i = 0, l = target.length; i < l; i++) {
    t = target[i].node;
    sorterResult = utils.nodeSorter(t.element, firstFromFrame.element);
    if (sorterResult > 0 || (sorterResult === 0 && firstFromFrame.selector.length < t.selector.length)) {
      target.splice.apply(target, [i, 0].concat(to));
      return;
    }
  }

  target.push.apply(target, to);
}

function normalizeResult(result) {
  'use strict';

  if (!result || !result.results) {
    return null;
  }

  if (!Array.isArray(result.results)) {
    return [result.results];
  }

  if (!result.results.length) {
    return null;
  }

  return result.results;

}

/**
* Merges one or more RuleResults (possibly from different frames) into one RuleResult
* @private
* @param  {Array} frameResults  Array of objects including the RuleResults as `results` and frame as `frame`
* @return {Array}              The merged RuleResults; should only have one result per rule
*/
utils.mergeResults = function mergeResults(frameResults) {
  'use strict';
  var result = [];
  frameResults.forEach(function (frameResult) {
    var results = normalizeResult(frameResult);
    if (!results || !results.length) {
      return;
    }

    results.forEach(function (ruleResult) {
      if (ruleResult.nodes && frameResult.frame) {
        pushFrame(ruleResult.nodes, frameResult.frameElement, frameResult.frame);
      }

      var res = utils.findBy(result, 'id', ruleResult.id);
      if (!res) {
        result.push(ruleResult);
      } else {
        if (ruleResult.nodes.length) {
          spliceNodes(res.nodes, ruleResult.nodes);
        }
      }
    });
  });
  return result;
};

/**
 * Array#sort callback to sort nodes by DOM order
 * @private
 * @param  {Node} a
 * @param  {Node} b
 * @return {Integer}   @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Sort
 */
utils.nodeSorter = function nodeSorter(a, b) {
	/*jshint bitwise: false */

	'use strict';

	if (a === b) {
		return 0;
	}

	if (a.compareDocumentPosition(b) & 4) { // a before b
		return -1;
	}

	return 1; // b before a

};


/**
 * Publish metadata from axe._audit.data
 * @param  {RuleResult} result Result to publish to
 * @private
 */
utils.publishMetaData = function (ruleResult) {
	'use strict';

	function extender(shouldBeTrue) {
		return function (check) {
			var sourceData = checksData[check.id] || {};
			var messages = sourceData.messages || {};
			var data = utils.extendBlacklist({}, sourceData, ['messages']);
			data.message = check.result === shouldBeTrue ? messages.pass : messages.fail;
			utils.extendMetaData(check, data);
		};
	}

	var checksData = axe._audit.data.checks || {};
	var rulesData = axe._audit.data.rules || {};
	var rule = utils.findBy(axe._audit.rules, 'id', ruleResult.id) || {};

	ruleResult.tags = utils.clone(rule.tags || []);

	var shouldBeTrue = extender(true);
	var shouldBeFalse = extender(false);
	ruleResult.nodes.forEach(function (detail) {
		detail.any.forEach(shouldBeTrue);
		detail.all.forEach(shouldBeTrue);
		detail.none.forEach(shouldBeFalse);
	});
	utils.extendMetaData(ruleResult, utils.clone(rulesData[ruleResult.id] || {}));
};

(function () {
	'use strict';
	function noop() {}

	/**
	 * Create an asyncronous "queue", list of functions to be invoked in parallel, but not necessarily returned in order
	 * @return {Queue} The newly generated "queue"
	 */
	function queue() {
		var tasks = [],
			started = 0,
			remaining = 0, // number of tasks not yet finished
			awt = noop;

		function pop() {
			var length = tasks.length;
			for (; started < length; started++) {
				var task = tasks[started],
					fn = task.shift();

				task.push(callback(started));
				fn.apply(null, task);
			}
		}

		function callback(i) {
			return function (r) {
				tasks[i] = r;
				if (!--remaining) {
					notify();
				}
			};
		}

		function notify() {
			awt(tasks);
		}

		return {
			/**
			 * Defer a function that may or may not run asynchronously.
			 *
			 * First parameter should be the function to execute with subsequent
			 * parameters being passed as arguments to that function
			 */
			defer: function (fn) {
				tasks.push([fn]);
				++remaining;
				pop();
			},
			/**
			 * The callback to execute once all "deferred" functions have completed.  Will only be invoked once.
			 * @param  {Function} f The callback, receives an array of the return/callbacked
			 * values of each of the "deferred" functions
			 */
			then: function (f) {
				awt = f;
				if (!remaining) {
					notify();
				}
			},
			/**
			 * Abort the "queue" and prevent `then` function from firing
			 * @param  {Function} fn The callback to execute; receives an array of the results which have completed
			 */
			abort: function (fn) {
				awt = noop;
				fn(tasks);
			}
		};
	}

	utils.queue = queue;
})();

/*global uuid */
(function (exports) {
	'use strict';
	var messages = {},
		subscribers = {};

	/**
	 * Verify the received message is from the "respondable" module
	 * @private
	 * @param  {Object} postedMessage The message received via postMessage
	 * @return {Boolean}              `true` if the message is verified from respondable
	 */
	function verify(postedMessage) {
		return typeof postedMessage === 'object' && typeof postedMessage.uuid === 'string' &&
			postedMessage._respondable === true;
	}

	/**
	 * Posts the message to correct frame.
	 * This abstraction necessary because IE9 & 10 do not support posting Objects; only strings
	 * @private
	 * @param  {Window}   win      The `window` to post the message to
	 * @param  {String}   topic    The topic of the message
	 * @param  {Object}   message  The message content
	 * @param  {String}   uuid     The UUID, or pseudo-unique ID of the message
	 * @param  {Function} callback The function to invoke when/if the message is responded to
	 */
	function post(win, topic, message, uuid, callback) {

		var data = {
			uuid: uuid,
			topic: topic,
			message: message,
			_respondable: true
		};

		messages[uuid] = callback;
		win.postMessage(JSON.stringify(data), '*');
	}

	/**
	 * Post a message to a window who may or may not respond to it.
	 * @param  {Window}   win      The window to post the message to
	 * @param  {String}   topic    The topic of the message
	 * @param  {Object}   message  The message content
	 * @param  {Function} callback The function to invoke when/if the message is responded to
	 */
	function respondable(win, topic, message, callback) {
		var id = uuid.v1();
		post(win, topic, message, id, callback);
	}

	/**
	 * Subscribe to messages sent via the `respondable` module.
	 * @param  {String}   topic    The topic to listen to
	 * @param  {Function} callback The function to invoke when a message is received
	 */
	respondable.subscribe = function (topic, callback) {
		subscribers[topic] = callback;
	};

	/**
	 * Publishes the "respondable" message to the appropriate subscriber
	 * @private
	 * @param  {Event} event The event object of the postMessage
	 * @param  {Object} data  The data sent with the message
	 */
	function publish(event, data) {
		var topic = data.topic,
			message = data.message,
			subscriber = subscribers[topic];
		if (subscriber) {
			subscriber(message, createResponder(event.source, null, data.uuid));
		}
	}

	/**
	 * Helper closure to create a function that may be used to respond to a message
	 * @private
	 * @param  {Window} source The window from which the message originated
	 * @param  {String} topic  The topic of the message
	 * @param  {String} uuid   The "unique" ID of the original message
	 * @return {Function}      A function that may be invoked to respond to the message
	 */
	function createResponder(source, topic, uuid) {
		return function (message, callback) {
			post(source, topic, message, uuid, callback);
		};
	}

	window.addEventListener('message', function (e) {

		if (typeof e.data !== 'string') {
			return;
		}

		var data;
		try {
			data = JSON.parse(e.data);
		} catch(ex) {}

		if (!verify(data)) {
			return;
		}

		var uuid = data.uuid;
		if (messages[uuid]) {
			messages[uuid](data.message, createResponder(e.source, data.topic, uuid));
			messages[uuid] = null;
		}

		publish(e, data);
	}, false);

	exports.respondable = respondable;

}(utils));


/**
 * Determines whether a rule should run
 * @param  {Rule}    rule     The rule to test
 * @param  {Context} context  The context of the Audit
 * @param  {Object}  options  Options object
 * @return {Boolean}
 */
utils.ruleShouldRun = function (rule, context, options) {
	'use strict';
	if (rule.pageLevel && !context.page) {
		return false;
	}

	var runOnly = options.runOnly,
		ruleOptions = (options.rules || {})[rule.id];

	if (runOnly) {
		if (runOnly.type === 'rule') {
			return runOnly.values.indexOf(rule.id) !== -1;
		}

		return !!(runOnly.values || []).filter(function (item) {
			return rule.tags.indexOf(item) !== -1;
		}).length;
	}

	if ((ruleOptions && ruleOptions.hasOwnProperty('enabled')) ? !ruleOptions.enabled : !rule.enabled) {
		return false;
	}

	return true;
};
/**
 * Get the deepest node in a given collection
 * @private
 * @param  {Array} collection Array of nodes to test
 * @return {Node}             The deepest node
 */
function getDeepest(collection) {
	'use strict';

	return collection.sort(function (a, b) {
		if (utils.contains(a, b)) {
			return 1;
		}
		return -1;
	})[0];

}

/**
 * Determines if a node is included or excluded in a given context
 * @private
 * @param  {Node}  node     The node to test
 * @param  {Object}  context "Resolved" context object, @see resolveContext
 * @return {Boolean}         [description]
 */
function isNodeInContext(node, context) {
	'use strict';

	var include = context.include && getDeepest(context.include.filter(function (candidate) {
		return utils.contains(candidate, node);
	}));
	var exclude = context.exclude && getDeepest(context.exclude.filter(function (candidate) {
		return utils.contains(candidate, node);
	}));
	if ((!exclude && include) || (exclude && utils.contains(exclude, include))) {
		return true;
	}
	return false;
}

/**
 * Pushes unique nodes that are in context to an array
 * @private
 * @param  {Array} result  The array to push to
 * @param  {Array} nodes   The list of nodes to push
 * @param  {Object} context The "resolved" context object, @see resolveContext
 */
function pushNode(result, nodes, context) {
	'use strict';

	for (var i = 0, l = nodes.length; i < l; i++) {
		if (result.indexOf(nodes[i]) === -1 && isNodeInContext(nodes[i], context)) {
			result.push(nodes[i]);
		}
	}
}

/**
 * Selects elements which match `select` that are included and excluded via the `Context` object
 * @param  {String} selector  CSS selector of the HTMLElements to select
 * @param  {Context} context  The "resolved" context object, @see Context
 * @return {Array}            Matching nodes sorted by DOM order
 */
utils.select = function select(selector, context) {
	'use strict';

	var result = [], candidate;
	for (var i = 0, l = context.include.length; i < l; i++) {
		candidate = context.include[i];
		if (candidate.nodeType === candidate.ELEMENT_NODE && utils.matchesSelector(candidate, selector)) {
			pushNode(result, [candidate], context);
		}
		pushNode(result, candidate.querySelectorAll(selector), context);
	}

	return result.sort(utils.nodeSorter);
};


/**
 * Converts array-like (numerical indicies and `length` property) structures to actual, real arrays
 * @param  {Mixed} thing Array-like thing to convert
 * @return {Array}
 */
utils.toArray = function (thing) {
	'use strict';
	return Array.prototype.slice.call(thing);
};
axe._load({"data":{"rules":{"accesskeys":{"description":"Ensures every accesskey attribute value is unique","help":"accesskey attribute value must be unique","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/accesskeys"},"area-alt":{"description":"Ensures <area> elements of image maps have alternate text","help":"Active <area> elements must have alternate text","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/area-alt"},"aria-allowed-attr":{"description":"Ensures ARIA attributes are allowed for an element's role","help":"Elements must only use allowed ARIA attributes","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-allowed-attr"},"aria-required-attr":{"description":"Ensures elements with ARIA roles have all required ARIA attributes","help":"Required ARIA attributes must be provided","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-required-attr"},"aria-required-children":{"description":"Ensures elements with an ARIA role that require child roles contain them","help":"Certain ARIA roles must contain particular children","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-required-children"},"aria-required-parent":{"description":"Ensures elements with an ARIA role that require parent roles are contained by them","help":"Certain ARIA roles must be contained by particular parents","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-required-parent"},"aria-roles":{"description":"Ensures all elements with a role attribute use a valid value","help":"ARIA roles used must conform to valid values","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-roles"},"aria-valid-attr-value":{"description":"Ensures all ARIA attributes have valid values","help":"ARIA attributes must conform to valid values","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-valid-attr-value"},"aria-valid-attr":{"description":"Ensures attributes that begin with aria- are valid ARIA attributes","help":"ARIA attributes must conform to valid names","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/aria-valid-attr"},"audio-caption":{"description":"Ensures <audio> elements have captions","help":"<audio> elements must have a captions track","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/audio-caption"},"blink":{"description":"Ensures <blink> elements are not used","help":"<blink> elements are deprecated and must not be used","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/blink"},"button-name":{"description":"Ensures buttons have discernible text","help":"Buttons must have discernible text","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/button-name"},"bypass":{"description":"Ensures each page has at least one mechanism for a user to bypass navigation and jump straight to the content","help":"Page must have means to bypass repeated blocks","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/bypass"},"checkboxgroup":{"description":"Ensures related <input type=\"checkbox\"> elements have a group and that that group designation is consistent","help":"Checkbox inputs with the same name attribute value must be part of a group","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/checkboxgroup"},"color-contrast":{"description":"Ensures the contrast between foreground and background colors meets WCAG 2 AA contrast ratio thresholds","help":"Elements must have sufficient color contrast","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/color-contrast"},"data-table":{"description":"Ensures data tables are marked up semantically and have the correct header structure","help":"Data tables should be marked up properly","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/data-table"},"definition-list":{"description":"Ensures <dl> elements are structured correctly","help":"<dl> elements must only directly contain properly-ordered <dt> and <dd> groups, <script> or <template> elements","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/definition-list"},"dlitem":{"description":"Ensures <dt> and <dd> elements are contained by a <dl>","help":"<dt> and <dd> elements must be contained by a <dl>","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/dlitem"},"document-title":{"description":"Ensures each HTML document contains a non-empty <title> element","help":"Documents must have <title> element to aid in navigation","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/document-title"},"duplicate-id":{"description":"Ensures every id attribute value is unique","help":"id attribute value must be unique","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/duplicate-id"},"empty-heading":{"description":"Ensures headings have discernible text","help":"Headings must not be empty","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/empty-heading"},"frame-title":{"description":"Ensures <iframe> and <frame> elements contain a unique and non-empty title attribute","help":"Frames must have unique title attribute","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/frame-title"},"heading-order":{"description":"Ensures the order of headings is semantically correct","help":"Heading levels should only increase by one","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/heading-order"},"html-lang":{"description":"Ensures every HTML document has a lang attribute and its value is valid","help":"<html> element must have a valid lang attribute","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/html-lang"},"image-alt":{"description":"Ensures <img> elements have alternate text or a role of none or presentation","help":"Images must have alternate text","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/image-alt"},"input-image-alt":{"description":"Ensures <input type=\"image\"> elements have alternate text","help":"Image buttons must have alternate text","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/input-image-alt"},"label-title-only":{"description":"Ensures that every form element is not solely labeled using the title or aria-describedby attributes","help":"Form elements should have a visible label","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/label-title-only"},"label":{"description":"Ensures every form element has a label","help":"Form elements must have labels","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/label"},"layout-table":{"description":"Ensures presentational <table> elements do not use <th>, <caption> elements or the summary attribute","help":"Layout tables must not use data table elements","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/layout-table"},"link-name":{"description":"Ensures links have discernible text","help":"Links must have discernible text","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/link-name"},"list":{"description":"Ensures that lists are structured correctly","help":"<ul> and <ol> must only directly contain <li>, <script> or <template> elements","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/list"},"listitem":{"description":"Ensures <li> elements are used semantically","help":"<li> elements must be contained in a <ul> or <ol>","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/listitem"},"marquee":{"description":"Ensures <marquee> elements are not used","help":"<marquee> elements are deprecated and must not be used","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/marquee"},"meta-refresh":{"description":"Ensures <meta http-equiv=\"refresh\"> is not used","help":"Timed refresh must not exist","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/meta-refresh"},"meta-viewport":{"description":"Ensures <meta name=\"viewport\"> does not disable text scaling and zooming","help":"Zooming and scaling must not be disabled","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/meta-viewport"},"object-alt":{"description":"Ensures <object> elements have alternate text","help":"<object> elements must have alternate text","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/object-alt"},"radiogroup":{"description":"Ensures related <input type=\"radio\"> elements have a group and that the group designation is consistent","help":"Radio inputs with the same name attribute value must be part of a group","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/radiogroup"},"region":{"description":"Ensures all content is contained within a landmark region","help":"Content should be contained in a landmark region","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/region"},"scope":{"description":"Ensures the scope attribute is used correctly on tables","help":"scope attribute should be used correctly","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/scope"},"server-side-image-map":{"description":"Ensures that server-side image maps are not used","help":"Server-side image maps must not be used","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/server-side-image-map"},"skip-link":{"description":"Ensures the first link on the page is a skip link","help":"The page should have a skip link as its first link","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/skip-link"},"tabindex":{"description":"Ensures tabindex attribute values are not greater than 0","help":"Elements should not have tabindex greater than zero","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/tabindex"},"valid-lang":{"description":"Ensures lang attributes have valid values","help":"lang attribute must have a valid value","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/valid-lang"},"video-caption":{"description":"Ensures <video> elements have captions","help":"<video> elements must have captions","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/video-caption"},"video-description":{"description":"Ensures <video> elements have audio descriptions","help":"<video> elements must have an audio description track","helpUrl":"https://dequeuniversity.com/rules/axe/1.1/video-description"}},"checks":{"accesskeys":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Accesskey attribute value is unique';return out;
},"fail":function anonymous(it
/**/) {
var out='Document has multiple elements with the same accesskey';return out;
}}},"non-empty-alt":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element has a non-empty alt attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='Element has no alt attribute or the alt attribute is empty';return out;
}}},"aria-label":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='aria-label attribute exists and is not empty';return out;
},"fail":function anonymous(it
/**/) {
var out='aria-label attribute does not exist or is empty';return out;
}}},"aria-labelledby":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='aria-labelledby attribute exists and references elements that are visible to screen readers';return out;
},"fail":function anonymous(it
/**/) {
var out='aria-labelledby attribute does not exist, references elements that do not exist or references elements that are empty or not visible';return out;
}}},"aria-allowed-attr":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='ARIA attributes are used correctly for the defined role';return out;
},"fail":function anonymous(it
/**/) {
var out='ARIA attribute'+(it.data && it.data.length > 1 ? 's are' : ' is')+' not allowed:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;
}}},"aria-required-attr":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='All required ARIA attributes are present';return out;
},"fail":function anonymous(it
/**/) {
var out='Required ARIA attribute'+(it.data && it.data.length > 1 ? 's' : '')+' not present:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;
}}},"aria-required-children":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Required ARIA children are present';return out;
},"fail":function anonymous(it
/**/) {
var out='Required ARIA '+(it.data && it.data.length > 1 ? 'children' : 'child')+' role not present:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;
}}},"aria-required-parent":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Required ARIA parent role present';return out;
},"fail":function anonymous(it
/**/) {
var out='Required ARIA parent'+(it.data && it.data.length > 1 ? 's' : '')+' role not present:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;
}}},"invalidrole":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='ARIA role is valid';return out;
},"fail":function anonymous(it
/**/) {
var out='Role must be one of the valid ARIA roles';return out;
}}},"abstractrole":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Abstract roles are not used';return out;
},"fail":function anonymous(it
/**/) {
var out='Abstract roles cannot be directly used';return out;
}}},"aria-valid-attr-value":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='ARIA attribute values are valid';return out;
},"fail":function anonymous(it
/**/) {
var out='Invalid ARIA attribute value'+(it.data && it.data.length > 1 ? 's' : '')+':';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;
}}},"aria-valid-attr":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='ARIA attribute name'+(it.data && it.data.length > 1 ? 's' : '')+' are valid';return out;
},"fail":function anonymous(it
/**/) {
var out='Invalid ARIA attribute name'+(it.data && it.data.length > 1 ? 's' : '')+':';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;
}}},"caption":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='The multimedia element has a captions track';return out;
},"fail":function anonymous(it
/**/) {
var out='The multimedia element does not have a captions track';return out;
}}},"exists":{"impact":"minor","messages":{"pass":function anonymous(it
/**/) {
var out='Element does not exist';return out;
},"fail":function anonymous(it
/**/) {
var out='Element exists';return out;
}}},"non-empty-if-present":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element ';if(it.data){out+='has a non-empty value attribute';}else{out+='does not have a value attribute';}return out;
},"fail":function anonymous(it
/**/) {
var out='Element has a value attribute and the value attribute is empty';return out;
}}},"non-empty-value":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element has a non-empty value attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='Element has no value attribute or the value attribute is empty';return out;
}}},"button-has-visible-text":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element has inner text that is visible to screen readers';return out;
},"fail":function anonymous(it
/**/) {
var out='Element does not have inner text that is visible to screen readers';return out;
}}},"role-presentation":{"impact":"moderate","messages":{"pass":function anonymous(it
/**/) {
var out='Element\'s default semantics were overriden with role="presentation"';return out;
},"fail":function anonymous(it
/**/) {
var out='Element\'s default semantics were not overridden with role="presentation"';return out;
}}},"role-none":{"impact":"moderate","messages":{"pass":function anonymous(it
/**/) {
var out='Element\'s default semantics were overriden with role="none"';return out;
},"fail":function anonymous(it
/**/) {
var out='Element\'s default semantics were not overridden with role="none"';return out;
}}},"duplicate-img-label":{"impact":"minor","messages":{"pass":function anonymous(it
/**/) {
var out='Element does not duplicate existing text in <img> alt text';return out;
},"fail":function anonymous(it
/**/) {
var out='Element contains <img> element with alt text that duplicates existing text';return out;
}}},"focusable-no-name":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Element is not in tab order or has accessible text';return out;
},"fail":function anonymous(it
/**/) {
var out='Element is in tab order and does not have accessible text';return out;
}}},"internal-link-present":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Valid skip link found';return out;
},"fail":function anonymous(it
/**/) {
var out='No valid skip link found';return out;
}}},"header-present":{"impact":"moderate","messages":{"pass":function anonymous(it
/**/) {
var out='Page has a header';return out;
},"fail":function anonymous(it
/**/) {
var out='Page does not have a header';return out;
}}},"landmark":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Page has a landmark region';return out;
},"fail":function anonymous(it
/**/) {
var out='Page does not have a landmark region';return out;
}}},"group-labelledby":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='All elements with the name "'+(it.data.name)+'" reference the same element with aria-labelledby';return out;
},"fail":function anonymous(it
/**/) {
var out='All elements with the name "'+(it.data.name)+'" do not reference the same element with aria-labelledby';return out;
}}},"fieldset":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element is contained in a fieldset';return out;
},"fail":function anonymous(it
/**/) {
var out='';var code = it.data && it.data.failureCode;if(code === 'no-legend'){out+='Fieldset does not have a legend as its first child';}else if(code === 'empty-legend'){out+='Legend does not have text that is visible to screen readers';}else if(code === 'mixed-inputs'){out+='Fieldset contains unrelated inputs';}else if(code === 'no-group-label'){out+='ARIA group does not have aria-label or aria-labelledby';}else if(code === 'group-mixed-inputs'){out+='ARIA group contains unrelated inputs';}else{out+='Element does not have a containing fieldset or ARIA group';}return out;
}}},"color-contrast":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='';if(it.data && it.data.contrastRatio){out+='Element has sufficient color contrast of '+(it.data.contrastRatio);}else{out+='Unable to determine contrast ratio';}return out;
},"fail":function anonymous(it
/**/) {
var out='Element has insufficient color contrast of '+(it.data.contrastRatio)+' (foreground color: '+(it.data.fgColor)+', background color: '+(it.data.bgColor)+', font size: '+(it.data.fontSize)+', font weight: '+(it.data.fontWeight)+')';return out;
}}},"consistent-columns":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Table has consistent column widths';return out;
},"fail":function anonymous(it
/**/) {
var out='Table does not have the same number of columns in every row';return out;
}}},"cell-no-header":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='All data cells have table headers';return out;
},"fail":function anonymous(it
/**/) {
var out='Some data cells do not have table headers';return out;
}}},"headers-visible-text":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Header cell has visible text';return out;
},"fail":function anonymous(it
/**/) {
var out='Header cell does not have visible text';return out;
}}},"headers-attr-reference":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='headers attribute references elements that are visible to screen readers';return out;
},"fail":function anonymous(it
/**/) {
var out='headers attribute references element that is not visible to screen readers';return out;
}}},"th-scope":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='<th> elements use scope attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='<th> elements must use scope attribute';return out;
}}},"no-caption":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Table has a <caption>';return out;
},"fail":function anonymous(it
/**/) {
var out='Table does not have a <caption>';return out;
}}},"th-headers-attr":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='<th> elements do not use headers attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='<th> elements should not use headers attribute';return out;
}}},"th-single-row-column":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='<th> elements are used when there is only a single row and single column of headers';return out;
},"fail":function anonymous(it
/**/) {
var out='<th> elements should only be used when there is a single row and single column of headers';return out;
}}},"same-caption-summary":{"impact":"moderate","messages":{"pass":function anonymous(it
/**/) {
var out='Content of summary attribute and <caption> are not duplicated';return out;
},"fail":function anonymous(it
/**/) {
var out='Content of summary attribute and <caption> element are indentical';return out;
}}},"rowspan":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Table does not have cells with rowspan attribute greater than 1';return out;
},"fail":function anonymous(it
/**/) {
var out='Table has cells whose rowspan attribute is not equal to 1';return out;
}}},"structured-dlitems":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='When not empty, element has both <dt> and <dd> elements';return out;
},"fail":function anonymous(it
/**/) {
var out='When not empty, element does not have at least one <dt> element followed by at least one <dd> element';return out;
}}},"only-dlitems":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Element only has children that are <dt> or <dd> elements';return out;
},"fail":function anonymous(it
/**/) {
var out='Element has children that are not <dt> or <dd> elements';return out;
}}},"dlitem":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Description list item has a <dl> parent element';return out;
},"fail":function anonymous(it
/**/) {
var out='Description list item does not have a <dl> parent element';return out;
}}},"doc-has-title":{"impact":"moderate","messages":{"pass":function anonymous(it
/**/) {
var out='Document has a non-empty <title> element';return out;
},"fail":function anonymous(it
/**/) {
var out='Document does not have a non-empty <title> element';return out;
}}},"duplicate-id":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Document has no elements that share the same id attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='Document has multiple elements with the same id attribute: '+(it.data);return out;
}}},"has-visible-text":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element has text that is visible to screen readers';return out;
},"fail":function anonymous(it
/**/) {
var out='Element does not have text that is visible to screen readers';return out;
}}},"non-empty-title":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element has a title attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='Element has no title attribute or the title attribute is empty';return out;
}}},"unique-frame-title":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Element\'s title attribute is unique';return out;
},"fail":function anonymous(it
/**/) {
var out='Element\'s title attribute is not unique';return out;
}}},"heading-order":{"impact":"minor","messages":{"pass":function anonymous(it
/**/) {
var out='Heading order valid';return out;
},"fail":function anonymous(it
/**/) {
var out='Heading order invalid';return out;
}}},"has-lang":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='The <html> element has a lang attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='The <html> element does not have a lang attribute';return out;
}}},"valid-lang":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Value of lang attribute is included in the list of valid languages';return out;
},"fail":function anonymous(it
/**/) {
var out='Value of lang attribute not included in the list of valid languages';return out;
}}},"has-alt":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Element has an alt attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='Element does not have an alt attribute';return out;
}}},"title-only":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Form element does not solely use title attribute for its label';return out;
},"fail":function anonymous(it
/**/) {
var out='Only title used to generate label for form element';return out;
}}},"implicit-label":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Form element has an implicit (wrapped) <label>';return out;
},"fail":function anonymous(it
/**/) {
var out='Form element does not have an implicit (wrapped) <label>';return out;
}}},"explicit-label":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Form element has an explicit <label>';return out;
},"fail":function anonymous(it
/**/) {
var out='Form element does not have an explicit <label>';return out;
}}},"help-same-as-label":{"impact":"minor","messages":{"pass":function anonymous(it
/**/) {
var out='Help text (title or aria-describedby) does not duplicate label text';return out;
},"fail":function anonymous(it
/**/) {
var out='Help text (title or aria-describedby) text is the same as the label text';return out;
}}},"multiple-label":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Form element does not have multiple <label> elements';return out;
},"fail":function anonymous(it
/**/) {
var out='Form element has multiple <label> elements';return out;
}}},"has-th":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Layout table does not use <th> elements';return out;
},"fail":function anonymous(it
/**/) {
var out='Layout table uses <th> elements';return out;
}}},"has-caption":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Layout table does not use <caption> element';return out;
},"fail":function anonymous(it
/**/) {
var out='Layout table uses <caption> element';return out;
}}},"has-summary":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Layout table does not use summary attribute';return out;
},"fail":function anonymous(it
/**/) {
var out='Layout table uses summary attribute';return out;
}}},"only-listitems":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='List element only has children that are <li>, <script> or <template> elements';return out;
},"fail":function anonymous(it
/**/) {
var out='List element has children that are not <li>, <script> or <template> elements';return out;
}}},"listitem":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='List item has a <ul>, <ol> or role="list" parent element';return out;
},"fail":function anonymous(it
/**/) {
var out='List item does not have a <ul>, <ol> or role="list" parent element';return out;
}}},"meta-refresh":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='<meta> tag does not immediately refresh the page';return out;
},"fail":function anonymous(it
/**/) {
var out='<meta> tag forces timed refresh of page';return out;
}}},"meta-viewport":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='<meta> tag does not disable zooming';return out;
},"fail":function anonymous(it
/**/) {
var out='<meta> tag disables zooming';return out;
}}},"region":{"impact":"moderate","messages":{"pass":function anonymous(it
/**/) {
var out='Content contained by ARIA landmark';return out;
},"fail":function anonymous(it
/**/) {
var out='Content not contained by an ARIA landmark';return out;
}}},"html5-scope":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Scope attribute is only used on table header elements (<th>)';return out;
},"fail":function anonymous(it
/**/) {
var out='In HTML 5, scope attributes may only be used on table header elements (<th>)';return out;
}}},"html4-scope":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Scope attribute is only used on table cell elements (<th> and <td>)';return out;
},"fail":function anonymous(it
/**/) {
var out='In HTML 4, the scope attribute may only be used on table cell elements (<th> and <td>)';return out;
}}},"scope-value":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Scope attribute is used correctly';return out;
},"fail":function anonymous(it
/**/) {
var out='The value of the scope attribute may only be \'row\' or \'col\'';return out;
}}},"skip-link":{"impact":"critical","messages":{"pass":function anonymous(it
/**/) {
var out='Valid skip link found';return out;
},"fail":function anonymous(it
/**/) {
var out='No valid skip link found';return out;
}}},"tabindex":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='Element does not have a tabindex greater than 0';return out;
},"fail":function anonymous(it
/**/) {
var out='Element has a tabindex greater than 0';return out;
}}},"description":{"impact":"serious","messages":{"pass":function anonymous(it
/**/) {
var out='The multimedia element has an audio description track';return out;
},"fail":function anonymous(it
/**/) {
var out='The multimedia element does not have an audio description track';return out;
}}}},"failureSummaries":{"any":{"failureMessage":function anonymous(it
/**/) {
var out='Fix any of the following:';var arr1=it;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+='\n  '+(value.split('\n').join('\n  '));} } return out;
}},"none":{"failureMessage":function anonymous(it
/**/) {
var out='Fix all of the following:';var arr1=it;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+='\n  '+(value.split('\n').join('\n  '));} } return out;
}}}},"rules":[{"id":"accesskeys","selector":"[accesskey]","tags":["wcag2a","wcag211"],"all":[],"any":[],"none":["accesskeys"]},{"id":"area-alt","selector":"map area[href]","excludeHidden":false,"tags":["wcag2a","wcag111","section508","section508a"],"all":[],"any":["non-empty-alt","aria-label","aria-labelledby"],"none":[]},{"id":"aria-allowed-attr","tags":["wcag2a","wcag411"],"all":[],"any":["aria-allowed-attr"],"none":[]},{"id":"aria-required-attr","selector":"[role]","tags":["wcag2a","wcag411"],"all":[],"any":["aria-required-attr"],"none":[]},{"id":"aria-required-children","selector":"[role]","tags":["wcag2a","wcag411"],"all":[],"any":["aria-required-children"],"none":[]},{"id":"aria-required-parent","selector":"[role]","tags":["wcag2a","wcag411"],"all":[],"any":["aria-required-parent"],"none":[]},{"id":"aria-roles","selector":"[role]","tags":["wcag2a","wcag411"],"all":[],"any":[],"none":["invalidrole","abstractrole"]},{"id":"aria-valid-attr-value","tags":["wcag2a","wcag411"],"all":[],"any":[{"options":[],"id":"aria-valid-attr-value"}],"none":[]},{"id":"aria-valid-attr","tags":["wcag2a","wcag411"],"all":[],"any":[{"options":[],"id":"aria-valid-attr"}],"none":[]},{"id":"audio-caption","selector":"audio","excludeHidden":false,"tags":["wcag2a","wcag122","section508","section508a"],"all":[],"any":[],"none":["caption"]},{"id":"blink","selector":"blink","tags":["wcag2a","wcag222"],"all":[],"any":[],"none":["exists"]},{"id":"button-name","selector":"button, [role=\"button\"], input[type=\"button\"], input[type=\"submit\"], input[type=\"reset\"]","tags":["wcag2a","wcag412","section508","section508a"],"all":[],"any":["non-empty-if-present","non-empty-value","button-has-visible-text","aria-label","aria-labelledby","role-presentation","role-none"],"none":["duplicate-img-label","focusable-no-name"]},{"id":"bypass","selector":"html","pageLevel":true,"matches":function (node) {
return !!node.querySelector('a[href]');

},"tags":["wcag2a","wcag241","section508","section508o"],"all":[],"any":["internal-link-present","header-present","landmark"],"none":[]},{"id":"checkboxgroup","selector":"input[type=checkbox][name]","tags":["wcag2a","wcag131"],"all":[],"any":["group-labelledby","fieldset"],"none":[]},{"id":"color-contrast","options":{"noScroll":false},"selector":"*","tags":["wcag2aa","wcag143"],"all":[],"any":["color-contrast"],"none":[]},{"id":"data-table","selector":"table","matches":function (node) {
return commons.table.isDataTable(node);
},"tags":["wcag2a","wcag131"],"all":[],"any":["consistent-columns"],"none":["cell-no-header","headers-visible-text","headers-attr-reference","th-scope","no-caption","th-headers-attr","th-single-row-column","same-caption-summary","rowspan"]},{"id":"definition-list","selector":"dl:not([role])","tags":["wcag2a","wcag131"],"all":[],"any":[],"none":["structured-dlitems","only-dlitems"]},{"id":"dlitem","selector":"dd:not([role]), dt:not([role])","tags":["wcag2a","wcag131"],"all":[],"any":["dlitem"],"none":[]},{"id":"document-title","selector":"html","tags":["wcag2a","wcag242"],"all":[],"any":["doc-has-title"],"none":[]},{"id":"duplicate-id","selector":"[id]","tags":["wcag2a","wcag411"],"all":[],"any":["duplicate-id"],"none":[]},{"id":"empty-heading","selector":"h1, h2, h3, h4, h5, h6, [role=\"heading\"]","tags":["wcag2a","wcag131"],"all":[],"any":["has-visible-text","role-presentation","role-none"],"none":[]},{"id":"frame-title","selector":"frame, iframe","tags":["wcag2a","wcag241"],"all":[],"any":["non-empty-title"],"none":["unique-frame-title"]},{"id":"heading-order","selector":"h1,h2,h3,h4,h5,h6,[role=heading]","enabled":false,"tags":["best-practice"],"all":[],"any":["heading-order"],"none":[]},{"id":"html-lang","selector":"html","tags":["wcag2a","wcag311"],"all":[],"any":["has-lang"],"none":[{"options":["aa","ab","ae","af","ak","am","an","ar","as","av","ay","az","ba","be","bg","bh","bi","bm","bn","bo","br","bs","ca","ce","ch","co","cr","cs","cu","cv","cy","da","de","dv","dz","ee","el","en","eo","es","et","eu","fa","ff","fi","fj","fo","fr","fy","ga","gd","gl","gn","gu","gv","ha","he","hi","ho","hr","ht","hu","hy","hz","ia","id","ie","ig","ii","ik","in","io","is","it","iu","iw","ja","ji","jv","jw","ka","kg","ki","kj","kk","kl","km","kn","ko","kr","ks","ku","kv","kw","ky","la","lb","lg","li","ln","lo","lt","lu","lv","mg","mh","mi","mk","ml","mn","mo","mr","ms","mt","my","na","nb","nd","ne","ng","nl","nn","no","nr","nv","ny","oc","oj","om","or","os","pa","pi","pl","ps","pt","qu","rm","rn","ro","ru","rw","sa","sc","sd","se","sg","sh","si","sk","sl","sm","sn","so","sq","sr","ss","st","su","sv","sw","ta","te","tg","th","ti","tk","tl","tn","to","tr","ts","tt","tw","ty","ug","uk","ur","uz","ve","vi","vo","wa","wo","xh","yi","yo","za","zh","zu"],"id":"valid-lang"}]},{"id":"image-alt","selector":"img","tags":["wcag2a","wcag111","section508","section508a"],"all":[],"any":["has-alt","aria-label","aria-labelledby","non-empty-title","role-presentation","role-none"],"none":[]},{"id":"input-image-alt","selector":"input[type=\"image\"]","tags":["wcag2a","wcag111","section508","section508a"],"all":[],"any":["non-empty-alt","aria-label","aria-labelledby"],"none":[]},{"id":"label-title-only","selector":"input:not([type='hidden']):not([type='image']):not([type='button']):not([type='submit']):not([type='reset']), select, textarea","enabled":false,"tags":["best-practice"],"all":[],"any":[],"none":["title-only"]},{"id":"label","selector":"input:not([type='hidden']):not([type='image']):not([type='button']):not([type='submit']):not([type='reset']), select, textarea","tags":["wcag2a","wcag332","wcag131","section508","section508n"],"all":[],"any":["aria-label","aria-labelledby","implicit-label","explicit-label","non-empty-title"],"none":["help-same-as-label","multiple-label"]},{"id":"layout-table","selector":"table","matches":function (node) {
return !commons.table.isDataTable(node);
},"tags":["wcag2a","wcag131"],"all":[],"any":[],"none":["has-th","has-caption","has-summary"]},{"id":"link-name","selector":"a[href]:not([role=\"button\"]), [role=link][href]","tags":["wcag2a","wcag111","wcag412","section508","section508a"],"all":[],"any":["has-visible-text","aria-label","aria-labelledby","role-presentation","role-none"],"none":["duplicate-img-label","focusable-no-name"]},{"id":"list","selector":"ul:not([role]), ol:not([role])","tags":["wcag2a","wcag131"],"all":[],"any":[],"none":["only-listitems"]},{"id":"listitem","selector":"li:not([role])","tags":["wcag2a","wcag131"],"all":[],"any":["listitem"],"none":[]},{"id":"marquee","selector":"marquee","tags":["wcag2a","wcag222","section508","section508j"],"all":[],"any":[],"none":["exists"]},{"id":"meta-refresh","selector":"meta[http-equiv=\"refresh\"]","excludeHidden":false,"tags":["wcag2a","wcag2aaa","wcag221","wcag224","wcag325"],"all":[],"any":["meta-refresh"],"none":[]},{"id":"meta-viewport","selector":"meta[name=\"viewport\"]","excludeHidden":false,"tags":["wcag2aa","wcag144"],"all":[],"any":["meta-viewport"],"none":[]},{"id":"object-alt","selector":"object","tags":["wcag2a","wcag111"],"all":[],"any":["has-visible-text"],"none":[]},{"id":"radiogroup","selector":"input[type=radio][name]","tags":["wcag2a","wcag131"],"all":[],"any":["group-labelledby","fieldset"],"none":[]},{"id":"region","selector":"html","pageLevel":true,"enabled":false,"tags":["best-practice"],"all":[],"any":["region"],"none":[]},{"id":"scope","selector":"[scope]","enabled":false,"tags":["best-practice"],"all":[],"any":["html5-scope","html4-scope"],"none":["scope-value"]},{"id":"server-side-image-map","selector":"img[ismap]","tags":["wcag2a","wcag211","section508","section508f"],"all":[],"any":[],"none":["exists"]},{"id":"skip-link","selector":"a[href]","pageLevel":true,"enabled":false,"tags":["best-practice"],"all":[],"any":["skip-link"],"none":[]},{"id":"tabindex","selector":"[tabindex]","tags":["best-practice"],"all":[],"any":["tabindex"],"none":[]},{"id":"valid-lang","selector":"[lang]:not(html), [xml\\:lang]:not(html)","tags":["wcag2aa","wcag312"],"all":[],"any":[],"none":[{"options":["aa","ab","ae","af","ak","am","an","ar","as","av","ay","az","ba","be","bg","bh","bi","bm","bn","bo","br","bs","ca","ce","ch","co","cr","cs","cu","cv","cy","da","de","dv","dz","ee","el","en","eo","es","et","eu","fa","ff","fi","fj","fo","fr","fy","ga","gd","gl","gn","gu","gv","ha","he","hi","ho","hr","ht","hu","hy","hz","ia","id","ie","ig","ii","ik","in","io","is","it","iu","iw","ja","ji","jv","jw","ka","kg","ki","kj","kk","kl","km","kn","ko","kr","ks","ku","kv","kw","ky","la","lb","lg","li","ln","lo","lt","lu","lv","mg","mh","mi","mk","ml","mn","mo","mr","ms","mt","my","na","nb","nd","ne","ng","nl","nn","no","nr","nv","ny","oc","oj","om","or","os","pa","pi","pl","ps","pt","qu","rm","rn","ro","ru","rw","sa","sc","sd","se","sg","sh","si","sk","sl","sm","sn","so","sq","sr","ss","st","su","sv","sw","ta","te","tg","th","ti","tk","tl","tn","to","tr","ts","tt","tw","ty","ug","uk","ur","uz","ve","vi","vo","wa","wo","xh","yi","yo","za","zh","zu"],"id":"valid-lang"}]},{"id":"video-caption","selector":"video","tags":["wcag2a","wcag122","wcag123","section508","section508a"],"all":[],"any":[],"none":["caption"]},{"id":"video-description","selector":"video","tags":["wcag2aa","wcag125","section508","section508a"],"all":[],"any":[],"none":["description"]}],"checks":[{"id":"abstractrole","evaluate":function (node, options) {
return commons.aria.getRoleType(node.getAttribute('role')) === 'abstract';

}},{"id":"aria-allowed-attr","matches":function (node) {

var role = node.getAttribute('role');
if (!role) {
	role = commons.aria.implicitRole(node);
}
var allowed = commons.aria.allowedAttr(role);
if (role && allowed) {
	var aria = /^aria-/;
	if (node.hasAttributes()) {
		var attrs = node.attributes;
		for (var i = 0, l = attrs.length; i < l; i++) {
			if (aria.test(attrs[i].nodeName)) {
				return true;
			}
		}
	}
}

return false;
},"evaluate":function (node, options) {
var invalid = [];

var attr, attrName, allowed,
	role = node.getAttribute('role'),
	attrs = node.attributes;

if (!role) {
	role = commons.aria.implicitRole(node);
}
allowed = commons.aria.allowedAttr(role);
if (role && allowed) {
	for (var i = 0, l = attrs.length; i < l; i++) {
		attr = attrs[i];
		attrName = attr.nodeName;
		if (commons.aria.validateAttr(attrName) && allowed.indexOf(attrName) === -1) {
			invalid.push(attrName + '="' + attr.nodeValue + '"');
		}
	}
}

if (invalid.length) {
	this.data(invalid);
	return false;
}

return true;
}},{"id":"invalidrole","evaluate":function (node, options) {
return !commons.aria.isValidRole(node.getAttribute('role'));



}},{"id":"aria-required-attr","evaluate":function (node, options) {
var missing = [];

if (node.hasAttributes()) {
	var attr,
		role = node.getAttribute('role'),
		required = commons.aria.requiredAttr(role);

	if (role && required) {
		for (var i = 0, l = required.length; i < l; i++) {
			attr = required[i];
			if (!node.getAttribute(attr)) {
				missing.push(attr);
			}
		}
	}
}

if (missing.length) {
	this.data(missing);
	return false;
}

return true;
}},{"id":"aria-required-children","evaluate":function (node, options) {
var requiredOwned = commons.aria.requiredOwned,
implicitNodes = commons.aria.implicitNodes,
matchesSelector = commons.utils.matchesSelector,
idrefs = commons.dom.idrefs;

function owns(node, role, ariaOwned) {
	if (node === null) { return false; }
	var implicit = implicitNodes(role),
	selector = ['[role="' + role + '"]'];

	if (implicit) {
		selector = selector.concat(implicit);
	}

	selector = selector.join(',');

	return ariaOwned ? (matchesSelector(node, selector) || !!node.querySelector(selector)) :
		!!node.querySelector(selector);
}

function ariaOwns(nodes, role) {
	var index, length;

	for (index = 0, length = nodes.length; index < length; index++) {
		if (nodes[index] === null) { continue; }
		if (owns(nodes[index], role, true)) {
			return true;
		}
	}
	return false;
}

function missingRequiredChildren(node, childRoles, all) {

	var i,
	l = childRoles.length,
	missing = [],
	ownedElements = idrefs(node, 'aria-owns');

	for (i = 0; i < l; i++) {
		var r = childRoles[i];
		if (owns(node, r) || ariaOwns(ownedElements, r)) {
			if (!all) { return null; }
		} else {
			if (all) { missing.push(r); }
		}
	}

	if (missing.length) { return missing; }
	if (!all && childRoles.length) { return childRoles; }
	return null;
}

var role = node.getAttribute('role');
var required = requiredOwned(role);

if (!required) { return true; }

var all = false;
var childRoles = required.one;
if (!childRoles) {
	var all = true;
	childRoles = required.all;
}

var missing = missingRequiredChildren(node, childRoles, all);

if (!missing) { return true; }

this.data(missing);
return false;

}},{"id":"aria-required-parent","evaluate":function (node, options) {
function getSelector(role) {
	var impliedNative = commons.aria.implicitNodes(role) || [];
	return impliedNative.concat('[role="' + role + '"]').join(',');
}

function getMissingContext(element, requiredContext, includeElement) {
	var index, length,
	role = element.getAttribute('role'),
	missing = [];

	if (!requiredContext) {
		requiredContext = commons.aria.requiredContext(role);
	}

	if (!requiredContext) { return null; }

	for (index = 0, length = requiredContext.length; index < length; index++) {
		if (includeElement && commons.utils.matchesSelector(element, getSelector(requiredContext[index]))) {
			return null;
		}
		if (commons.dom.findUp(element, getSelector(requiredContext[index]))) {
			//if one matches, it passes
			return null;
		} else {
			missing.push(requiredContext[index]);
		}
	}

	return missing;
}

function getAriaOwners(element) {
	var owners = [],
		o = null;

	while (element) {
		if (element.id) {
			o = document.querySelector('[aria-owns~=' + commons.utils.escapeSelector(element.id) + ']');
			if (o) { owners.push(o); }
		}
		element = element.parentNode;
	}

	return owners.length ? owners : null;
}

var missingParents = getMissingContext(node);

if (!missingParents) { return true; }

var owners = getAriaOwners(node);

if (owners) {
	for (var i = 0, l = owners.length; i < l; i++) {
		missingParents = getMissingContext(owners[i], missingParents, true);
		if (!missingParents) { return true; }
	}
}

this.data(missingParents);
return false;

}},{"id":"aria-valid-attr-value","matches":function (node) {
var aria = /^aria-/;
if (node.hasAttributes()) {
	var attrs = node.attributes;
	for (var i = 0, l = attrs.length; i < l; i++) {
		if (aria.test(attrs[i].nodeName)) {
			return true;
		}
	}
}

return false;
},"evaluate":function (node, options) {
options = Array.isArray(options) ? options : [];

var invalid = [],
	aria = /^aria-/;

var attr, attrName,
	attrs = node.attributes;

for (var i = 0, l = attrs.length; i < l; i++) {
	attr = attrs[i];
	attrName = attr.nodeName;
	if (options.indexOf(attrName) === -1 && aria.test(attrName) &&
		!commons.aria.validateAttrValue(node, attrName)) {

		invalid.push(attrName + '="' + attr.nodeValue + '"');
	}
}

if (invalid.length) {
	this.data(invalid);
	return false;
}

return true;

},"options":[]},{"id":"aria-valid-attr","matches":function (node) {
var aria = /^aria-/;
if (node.hasAttributes()) {
	var attrs = node.attributes;
	for (var i = 0, l = attrs.length; i < l; i++) {
		if (aria.test(attrs[i].nodeName)) {
			return true;
		}
	}
}

return false;
},"evaluate":function (node, options) {
options = Array.isArray(options) ? options : [];

var invalid = [],
	aria = /^aria-/;

var attr,
	attrs = node.attributes;

for (var i = 0, l = attrs.length; i < l; i++) {
	attr = attrs[i].nodeName;
	if (options.indexOf(attr) === -1 && aria.test(attr) && !commons.aria.validateAttr(attr)) {
		invalid.push(attr);
	}
}

if (invalid.length) {
	this.data(invalid);
	return false;
}

return true;

},"options":[]},{"id":"color-contrast","matches":function (node) {
var nodeName = node.nodeName.toUpperCase(),
	nodeType = node.type,
	doc = document;

if (nodeName === 'INPUT') {
	return ['hidden', 'range', 'color', 'checkbox', 'radio', 'image'].indexOf(nodeType) === -1 && !node.disabled;
}

if (nodeName === 'SELECT') {
	return !!node.options.length && !node.disabled;
}

if (nodeName === 'TEXTAREA') {
	return !node.disabled;
}

if (nodeName === 'OPTION') {
	return false;
}

if (nodeName === 'BUTTON' && node.disabled) {
	return false;
}

// check if the element is a label for a disabled control
if (nodeName === 'LABEL') {
	// explicit label of disabled input
	var candidate = node.htmlFor && doc.getElementById(node.htmlFor);
	if (candidate && candidate.disabled) {
		return false;
	}

	var candidate = node.querySelector('input:not([type="hidden"]):not([type="image"])' +
		':not([type="button"]):not([type="submit"]):not([type="reset"]), select, textarea');
	if (candidate && candidate.disabled) {
		return false;
	}

}

// label of disabled control associated w/ aria-labelledby
if (node.id) {
	var candidate = doc.querySelector('[aria-labelledby~=' + commons.utils.escapeSelector(node.id) + ']');
	if (candidate && candidate.disabled) {
		return false;
	}
}

if (commons.text.visible(node, false, true) === '') {
	return false;
}

var range = document.createRange(),
	childNodes = node.childNodes,
	length = childNodes.length,
	child, index;

for (index = 0; index < length; index++) {
	child = childNodes[index];

	if (child.nodeType === 3 && commons.text.sanitize(child.nodeValue) !== '') {
		range.selectNodeContents(child);
	}
}

var rects = range.getClientRects();
length = rects.length;

for (index = 0; index < length; index++) {
	//check to see if the rectangle impinges
	if (commons.dom.visuallyOverlaps(rects[index], node)) {
		return true;
	}
}

return false;

},"evaluate":function (node, options) {
var useScroll = !(options || {}).noScroll;
var bgNodes = [],
	bgColor = commons.color.getBackgroundColor(node, bgNodes, useScroll),
	fgColor = commons.color.getForegroundColor(node, useScroll);

//We don't know, so we'll pass it provisionally
if (fgColor === null || bgColor === null) {
	return true;
}

var nodeStyle = window.getComputedStyle(node);
var fontSize = parseFloat(nodeStyle.getPropertyValue('font-size'));
var fontWeight = nodeStyle.getPropertyValue('font-weight');
var bold = (['bold', 'bolder', '600', '700', '800', '900'].indexOf(fontWeight) !== -1);

var cr = commons.color.hasValidContrastRatio(bgColor, fgColor, fontSize, bold);

this.data({
	fgColor: fgColor.toHexString(),
	bgColor: bgColor.toHexString(),
	contrastRatio: cr.contrastRatio.toFixed(2),
	fontSize: (fontSize * 72 / 96).toFixed(1) + 'pt',
	fontWeight: bold ? 'bold' : 'normal',
});

if (!cr.isValid) {
	this.relatedNodes(bgNodes);
}
return cr.isValid;

}},{"id":"fieldset","evaluate":function (node, options) {
var failureCode,
	self = this;


function getUnrelatedElements(parent, name) {
	return commons.utils.toArray(parent.querySelectorAll('select,textarea,button,input:not([name="' + name +
		'"]):not([type="hidden"])'));
}

function checkFieldset(group, name) {

	var firstNode = group.firstElementChild;
	if (!firstNode || firstNode.nodeName.toUpperCase() !== 'LEGEND') {
		self.relatedNodes([group]);
		failureCode = 'no-legend';
		return false;
	}
	if (!commons.text.accessibleText(firstNode)) {
		self.relatedNodes([firstNode]);
		failureCode = 'empty-legend';
		return false;
	}
	var otherElements = getUnrelatedElements(group, name);
	if (otherElements.length) {
		self.relatedNodes(otherElements);
		failureCode = 'mixed-inputs';
		return false;
	}
	return true;
}

function checkARIAGroup(group, name) {

	var hasLabelledByText = commons.dom.idrefs(group, 'aria-labelledby').some(function (element) {
		return element && commons.text.accessibleText(element);
	});
	var ariaLabel = group.getAttribute('aria-label');
	if (!hasLabelledByText && !(ariaLabel && commons.text.sanitize(ariaLabel))) {
		self.relatedNodes(group);
		failureCode = 'no-group-label';
		return false;
	}

	var otherElements = getUnrelatedElements(group, name);
	if (otherElements.length) {
		self.relatedNodes(otherElements);
		failureCode = 'group-mixed-inputs';
		return false;
	}
	return true;
}

function spliceCurrentNode(nodes, current) {
	return commons.utils.toArray(nodes).filter(function (candidate) {
		return candidate !== current;
	});
}

function runCheck(element) {
	var name = commons.utils.escapeSelector(node.name);
	var matchingNodes = document.querySelectorAll('input[type="' +
		commons.utils.escapeSelector(node.type) + '"][name="' + name + '"]');
	if (matchingNodes.length < 2) {
		return true;
	}
	var fieldset = commons.dom.findUp(element, 'fieldset');
	var group = commons.dom.findUp(element, '[role="group"]' + (node.type === 'radio' ? ',[role="radiogroup"]' : ''));
	if (!group && !fieldset) {
		failureCode = 'no-group';
		self.relatedNodes(spliceCurrentNode(matchingNodes, element));
		return false;
	}
	return fieldset ? checkFieldset(fieldset, name) : checkARIAGroup(group, name);

}

var data = {
	name: node.getAttribute('name'),
	type: node.getAttribute('type')
};

var result = runCheck(node);
if (!result) {
	data.failureCode = failureCode;
}
this.data(data);

return result;

},"after":function (results, options) {
var seen = {};

return results.filter(function (result) {
	// passes can pass through
	if (result.result) {
		return true;
	}
	var data = result.data;
	if (data) {
		seen[data.type] = seen[data.type] || {};
		if (!seen[data.type][data.name]) {
			seen[data.type][data.name] = [data];
			return true;
		}
		var hasBeenSeen = seen[data.type][data.name].some(function (candidate) {
			return candidate.failureCode === data.failureCode;
		});
		if (!hasBeenSeen) {
			seen[data.type][data.name].push(data);
		}

		return !hasBeenSeen;

	}
	return false;
});

}},{"id":"group-labelledby","evaluate":function (node, options) {
this.data({
	name: node.getAttribute('name'),
	type: node.getAttribute('type')
});

var matchingNodes = document.querySelectorAll('input[type="' +
	commons.utils.escapeSelector(node.type) + '"][name="' + commons.utils.escapeSelector(node.name) + '"]');
if (matchingNodes.length <= 1) {
	return true;
}

// Check to see if there's an aria-labelledby value that all nodes have in common
return [].map.call(matchingNodes, function (m) {
	var l = m.getAttribute('aria-labelledby');
	return l ? l.split(/\s+/) : [];
}).reduce(function (prev, curr) {
	return prev.filter(function (n) {
		return curr.indexOf(n) !== -1;
	});
}).filter(function (n) {
	var labelNode = document.getElementById(n);
	return labelNode && commons.text.accessibleText(labelNode);
}).length !== 0;

},"after":function (results, options) {
var seen = {};

return results.filter(function (result) {
	var data = result.data;
	if (data) {
		seen[data.type] = seen[data.type] || {};
		if (!seen[data.type][data.name]) {
			seen[data.type][data.name] = true;
			return true;
		}
	}
	return false;
});
}},{"id":"accesskeys","evaluate":function (node, options) {
this.data(node.getAttribute('accesskey'));
this.relatedNodes([node]);
return true;

},"after":function (results, options) {
var seen = {};
return results.filter(function (r) {
  if (!seen[r.data]) {
    seen[r.data] = r;
    r.relatedNodes = [];
    return true;
  }
  seen[r.data].relatedNodes.push(r.relatedNodes[0]);
  return false;
}).map(function (r) {
  r.result = !!r.relatedNodes.length;
  return r;
});

}},{"id":"focusable-no-name","evaluate":function (node, options) {
var tabIndex = node.getAttribute('tabindex'),
	isFocusable = commons.dom.isFocusable(node) && tabIndex > -1;
if (!isFocusable) {
	return false;
}
return !commons.text.accessibleText(node);

}},{"id":"tabindex","evaluate":function (node, options) {
return node.tabIndex <= 0;


}},{"id":"duplicate-img-label","evaluate":function (node, options) {
var imgs = node.querySelectorAll('img');
var text = commons.text.visible(node, true);

for (var i = 0, len = imgs.length; i < len; i++) {
	var imgAlt = commons.text.accessibleText(imgs[i]);
	if (imgAlt === text && text !== '') { return true; }
}

return false;

},"enabled":false},{"id":"explicit-label","evaluate":function (node, options) {

var label = document.querySelector('label[for="' + commons.utils.escapeSelector(node.id) + '"]');
if (label) {
	return !!commons.text.accessibleText(label);
}
return false;

},"selector":"[id]"},{"id":"help-same-as-label","evaluate":function (node, options) {

var labelText = commons.text.label(node),
	check = node.getAttribute('title');

if (!labelText) {
	return false;
}

if (!check) {
	check = '';

	if (node.getAttribute('aria-describedby')) {
		var ref = commons.dom.idrefs(node, 'aria-describedby');
		check = ref.map(function (thing) {
			return thing ? commons.text.accessibleText(thing) : '';
		}).join('');
	}
}

return commons.text.sanitize(check) === commons.text.sanitize(labelText);

},"enabled":false},{"id":"implicit-label","evaluate":function (node, options) {

var label = commons.dom.findUp(node, 'label');
if (label) {
	return !!commons.text.accessibleText(label);
}
return false;

}},{"id":"multiple-label","evaluate":function (node, options) {
var labels = [].slice.call(document.querySelectorAll('label[for="' +
	commons.utils.escapeSelector(node.id) + '"]')),
	parent = node.parentNode;

while (parent) {
	if (parent.tagName === 'LABEL' && labels.indexOf(parent) === -1) {
		labels.push(parent);
	}
	parent = parent.parentNode;
}

this.relatedNodes(labels);
return labels.length > 1;

}},{"id":"title-only","evaluate":function (node, options) {
var labelText = commons.text.label(node);
return !labelText && !!(node.getAttribute('title') || node.getAttribute('aria-describedby'));
}},{"id":"has-lang","evaluate":function (node, options) {
return node.hasAttribute('lang') || node.hasAttribute('xml:lang');
}},{"id":"valid-lang","options":["aa","ab","ae","af","ak","am","an","ar","as","av","ay","az","ba","be","bg","bh","bi","bm","bn","bo","br","bs","ca","ce","ch","co","cr","cs","cu","cv","cy","da","de","dv","dz","ee","el","en","eo","es","et","eu","fa","ff","fi","fj","fo","fr","fy","ga","gd","gl","gn","gu","gv","ha","he","hi","ho","hr","ht","hu","hy","hz","ia","id","ie","ig","ii","ik","in","io","is","it","iu","iw","ja","ji","jv","jw","ka","kg","ki","kj","kk","kl","km","kn","ko","kr","ks","ku","kv","kw","ky","la","lb","lg","li","ln","lo","lt","lu","lv","mg","mh","mi","mk","ml","mn","mo","mr","ms","mt","my","na","nb","nd","ne","ng","nl","nn","no","nr","nv","ny","oc","oj","om","or","os","pa","pi","pl","ps","pt","qu","rm","rn","ro","ru","rw","sa","sc","sd","se","sg","sh","si","sk","sl","sm","sn","so","sq","sr","ss","st","su","sv","sw","ta","te","tg","th","ti","tk","tl","tn","to","tr","ts","tt","tw","ty","ug","uk","ur","uz","ve","vi","vo","wa","wo","xh","yi","yo","za","zh","zu"],"evaluate":function (node, options) {
var lang = (node.getAttribute('lang') || '').trim().toLowerCase();
var xmlLang = (node.getAttribute('xml:lang') || '').trim().toLowerCase();
var invalid = [];

(options || []).forEach(function (cc) {
	cc = cc.toLowerCase();
	if (lang && (lang === cc || lang.indexOf(cc.toLowerCase() + '-') === 0)) {
		lang = null;
	}
	if (xmlLang && (xmlLang === cc || xmlLang.indexOf(cc.toLowerCase() + '-') === 0)) {
		xmlLang = null;
	}
});

if (xmlLang) {
	invalid.push('xml:lang="' + xmlLang + '"');
}
if (lang) {
	invalid.push('lang="' + lang + '"');
}

if (invalid.length) {
	this.data(invalid);
	return true;
}

return false;
}},{"id":"dlitem","evaluate":function (node, options) {
return node.parentNode.tagName === 'DL';


}},{"id":"has-listitem","evaluate":function (node, options) {
var children = node.children;
if (children.length === 0) { return true; }

for (var i = 0; i < children.length; i++) {
	if (children[i].nodeName.toUpperCase() === 'LI') { return false; }
}

return true;


}},{"id":"listitem","evaluate":function (node, options) {

if (['UL', 'OL'].indexOf(node.parentNode.nodeName.toUpperCase()) !== -1) {
	return true;
}

return node.parentNode.getAttribute('role') === 'list';

}},{"id":"only-dlitems","evaluate":function (node, options) {
var child,
	nodeName,
	bad = [],
	children = node.childNodes,
	hasNonEmptyTextNode = false;

for (var i = 0; i < children.length; i++) {
	child = children[i];
	nodeName = child.nodeName.toUpperCase();
	if (child.nodeType === 1 && (nodeName !== 'DT' && nodeName !== 'DD'&&
		nodeName !== 'SCRIPT' && nodeName !== 'TEMPLATE')) {
		bad.push(child);
	} else if (child.nodeType === 3 && child.nodeValue.trim() !== '') {
		hasNonEmptyTextNode = true;
	}
}
if (bad.length) {
	this.relatedNodes(bad);
}

var retVal = !!bad.length || hasNonEmptyTextNode;
return retVal;

}},{"id":"only-listitems","evaluate":function (node, options) {
var child,
	nodeName,
	bad = [],
	children = node.childNodes,
	hasNonEmptyTextNode = false;

for (var i = 0; i < children.length; i++) {
	child = children[i];
	nodeName = child.nodeName.toUpperCase();
	if (child.nodeType === 1 && nodeName !== 'LI' && nodeName !== 'SCRIPT' && nodeName !== 'TEMPLATE') {
		bad.push(child);
	} else if (child.nodeType === 3 && child.nodeValue.trim() !== '') {
		hasNonEmptyTextNode = true;
	}
}
if (bad.length) {
	this.relatedNodes(bad);
}

return !!bad.length || hasNonEmptyTextNode;

}},{"id":"structured-dlitems","evaluate":function (node, options) {
var children = node.children;
if ( !children || !children.length) { return false; }

var hasDt = false, hasDd = false, nodeName;
for (var i = 0; i < children.length; i++) {
	nodeName = children[i].nodeName.toUpperCase();
	if (nodeName === 'DT') { hasDt = true; }
	if (hasDt && nodeName === 'DD') { return false; }
	if (nodeName === 'DD') { hasDd = true; }
}

return hasDt || hasDd;

}},{"id":"caption","evaluate":function (node, options) {
return !(node.querySelector('track[kind=captions]'));

}},{"id":"description","evaluate":function (node, options) {
return !(node.querySelector('track[kind=descriptions]'));

}},{"id":"meta-viewport","evaluate":function (node, options) {
var params,
	content = node.getAttribute('content') || '',
	parsedParams = content.split(/[;,]/),
	result = {};

for (var i = 0, l = parsedParams.length; i < l; i++) {
	params = parsedParams[i].split('=');
	var key = params.shift();
	if (key && params.length) {
		result[key.trim()] = params.join('=').trim();
	}
}

if (result['maximum-scale'] && parseFloat(result['maximum-scale']) < 5) {
	return false;
}

if (result['user-scalable'] === 'no') {
	return false;
}


return true;
}},{"id":"header-present","selector":"html","evaluate":function (node, options) {
return !!node.querySelector('h1, h2, h3, h4, h5, h6, [role="heading"]');

}},{"id":"heading-order","evaluate":function (node, options) {
var ariaHeadingLevel = node.getAttribute('aria-level');

if (ariaHeadingLevel !== null) {
	this.data(parseInt(ariaHeadingLevel, 10));
	return true;
}

var headingLevel = node.tagName.match(/H(\d)/);

if (headingLevel) {
	this.data(parseInt(headingLevel[1], 10));
	return true;
}

return true;

},"after":function (results, options) {
if (results.length < 2) { return results; }

var prevLevel = results[0].data;

for (var i = 1; i < results.length; i++) {
	if (results[i].result && results[i].data > (prevLevel + 1)) { results[i].result = false; }
	prevLevel = results[i].data;
}

return results;

}},{"id":"internal-link-present","selector":"html","evaluate":function (node, options) {
return !!node.querySelector('a[href^="#"]');

}},{"id":"landmark","selector":"html","evaluate":function (node, options) {
return !!node.querySelector('[role="main"]');

}},{"id":"meta-refresh","evaluate":function (node, options) {
var content = node.getAttribute('content') || '',
	parsedParams = content.split(/[;,]/);

return (content === '' || parsedParams[0] === '0');

}},{"id":"region","evaluate":function (node, options) {
//jshint latedef: false

var landmarkRoles = commons.aria.getRolesByType('landmark'),
	firstLink = node.querySelector('a[href]');

function isSkipLink(n) {
	return firstLink &&
		commons.dom.isFocusable(commons.dom.getElementByReference(firstLink, 'href')) &&
		firstLink === n;
}

function isLandmark(n) {
	var role = n.getAttribute('role');
	return role && (landmarkRoles.indexOf(role) !== -1);
}

function checkRegion(n) {
	if (isLandmark(n)) { return null; }
	if (isSkipLink(n)) { return getViolatingChildren(n); }
	if (commons.dom.isVisible(n, true) &&
		(commons.text.visible(n, true, true) || commons.dom.isVisualContent(n))) { return n; }
	return getViolatingChildren(n);
}
function getViolatingChildren(n) {
	var children =  commons.utils.toArray(n.children);
	if (children.length === 0) { return []; }
	return children.map(checkRegion)
		.filter(function (c) { return c !== null; })
		.reduce(function (a, b) { return a.concat(b); }, []);
}

var v = getViolatingChildren(node);
this.relatedNodes(v);
return !v.length;

},"after":function (results, options) {
return [results[0]];

}},{"id":"skip-link","selector":"a[href]","evaluate":function (node, options) {
return commons.dom.isFocusable(commons.dom.getElementByReference(node, 'href'));

},"after":function (results, options) {
return [results[0]];

}},{"id":"unique-frame-title","evaluate":function (node, options) {
this.data(node.title);
return true;
},"after":function (results, options) {
var titles = {};
results.forEach(function (r) {
	titles[r.data] = titles[r.data] !== undefined ? ++titles[r.data] : 0;
});

return results.filter(function (r) {
	return !!titles[r.data];
});
}},{"id":"aria-label","evaluate":function (node, options) {
var label = node.getAttribute('aria-label');
return !!(label ? commons.text.sanitize(label).trim() : '');
}},{"id":"aria-labelledby","evaluate":function (node, options) {
var results = commons.dom.idrefs(node, 'aria-labelledby');
var element, i, l = results.length;

for (i = 0; i < l; i++) {
	element = results[i];
	if (element && commons.text.accessibleText(element).trim()) {
		return true;
	}
}

return false;

}},{"id":"button-has-visible-text","evaluate":function (node, options) {
return commons.text.accessibleText(node).length > 0;

},"selector":"button, [role=\"button\"]:not(input)"},{"id":"doc-has-title","evaluate":function (node, options) {
var title = document.title;
return !!(title ? commons.text.sanitize(title).trim() : '');
}},{"id":"duplicate-id","evaluate":function (node, options) {
var matchingNodes = document.querySelectorAll('[id="' + commons.utils.escapeSelector(node.id) + '"]');
var related = [];
for (var i = 0; i < matchingNodes.length; i++) {
	if (matchingNodes[i] !== node) {
		related.push(matchingNodes[i]);
	}
}
if (related.length) {
	this.relatedNodes(related);
}
this.data(node.getAttribute('id'));

return (matchingNodes.length <= 1);

},"after":function (results, options) {
var uniqueIds = [];
return results.filter(function (r) {
	if (uniqueIds.indexOf(r.data) === -1) {
		uniqueIds.push(r.data);
		return true;
	}
	return false;
});

}},{"id":"exists","evaluate":function (node, options) {
return true;
}},{"id":"has-alt","evaluate":function (node, options) {
return node.hasAttribute('alt');
}},{"id":"has-visible-text","evaluate":function (node, options) {
return commons.text.accessibleText(node).length > 0;

}},{"id":"non-empty-alt","evaluate":function (node, options) {
var label = node.getAttribute('alt');
return !!(label ? commons.text.sanitize(label).trim() : '');
}},{"id":"non-empty-if-present","evaluate":function (node, options) {
var label = node.getAttribute('value');
this.data(label);
return label === null || commons.text.sanitize(label).trim() !== '';

},"selector":"[type=\"submit\"], [type=\"reset\"]"},{"id":"non-empty-title","evaluate":function (node, options) {
var title = node.getAttribute('title');
return !!(title ? commons.text.sanitize(title).trim() : '');

}},{"id":"non-empty-value","evaluate":function (node, options) {
var label = node.getAttribute('value');
return !!(label ? commons.text.sanitize(label).trim() : '');

},"selector":"[type=\"button\"]"},{"id":"role-none","evaluate":function (node, options) {
return node.getAttribute('role') === 'none';
}},{"id":"role-presentation","evaluate":function (node, options) {
return node.getAttribute('role') === 'presentation';
}},{"id":"cell-no-header","evaluate":function (node, options) {


var row, cell,
	badCells = [];

for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (commons.table.isDataCell(cell) && (!commons.aria.label(cell) && !commons.table.getHeaders(cell).length)) {
			badCells.push(cell);
		}
	}
}

if (badCells.length) {
	this.relatedNodes(badCells);
	return true;
}

return false;

}},{"id":"consistent-columns","evaluate":function (node, options) {
var table = commons.table.toArray(node);
var relatedNodes = [];
var expectedWidth;
for (var i = 0, length = table.length; i < length; i++) {
	if (i === 0) {
		expectedWidth = table[i].length;
	} else if (expectedWidth !== table[i].length) {
		relatedNodes.push(node.rows[i]);
	}
}

return !relatedNodes.length;

}},{"id":"has-caption","evaluate":function (node, options) {
return !!node.caption;
}},{"id":"has-summary","evaluate":function (node, options) {
return !!node.summary;
}},{"id":"has-th","evaluate":function (node, options) {

var row, cell,
	badCells = [];

for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (cell.nodeName.toUpperCase() === 'TH') {
			badCells.push(cell);
		}
	}
}

if (badCells.length) {
	this.relatedNodes(badCells);
	return true;
}

return false;
}},{"id":"headers-attr-reference","evaluate":function (node, options) {
var row, cell, headerCells,
	badHeaders = [];

function checkHeader(header) {
	if (!header || !commons.text.accessibleText(header)) {
		badHeaders.push(cell);
	}
}

for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		headerCells = commons.dom.idrefs(cell, 'headers');
		if (headerCells.length) {
			headerCells.forEach(checkHeader);
		}
	}
}

if (badHeaders.length) {
	this.relatedNodes(badHeaders);
	return true;
}

return false;

}},{"id":"headers-visible-text","evaluate":function (node, options) {

var row, cell,
	badHeaders = [];
for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (commons.table.isHeader(cell) && !commons.text.accessibleText(cell)) {
			badHeaders.push(cell);
		}
	}
}

if (badHeaders.length) {
	this.relatedNodes(badHeaders);
	return true;
}

return false;

}},{"id":"html4-scope","evaluate":function (node, options) {

if (commons.dom.isHTML5(document)) {
	return false;
}

return node.nodeName.toUpperCase() === 'TH' || node.nodeName.toUpperCase() === 'TD';
}},{"id":"html5-scope","evaluate":function (node, options) {

if (!commons.dom.isHTML5(document)) {
	return false;
}

return node.nodeName.toUpperCase() === 'TH';
}},{"id":"no-caption","evaluate":function (node, options) {
return !(node.caption || {}).textContent;
},"enabled":false},{"id":"rowspan","evaluate":function (node, options) {
var row, cell,
	badCells = [];

for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (cell.rowSpan !== 1) {
			badCells.push(cell);
		}
	}
}

if (badCells.length) {
	this.relatedNodes(badCells);
	return true;
}

return false;
}},{"id":"same-caption-summary","selector":"table","evaluate":function (node, options) {
return !!(node.summary && node.caption) && node.summary === commons.text.accessibleText(node.caption);

}},{"id":"scope-value","evaluate":function (node, options) {
var value = node.getAttribute('scope');
return value !== 'row' && value !== 'col';
}},{"id":"th-headers-attr","evaluate":function (node, options) {

var row, cell,
	headersTH = [];
for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (cell.nodeName.toUpperCase() === 'TH' && cell.getAttribute('headers')) {
			headersTH.push(cell);
		}
	}
}

if (headersTH.length) {
	this.relatedNodes(headersTH);
	return true;
}

return false;
}},{"id":"th-scope","evaluate":function (node, options) {

var row, cell,
	noScopeTH = [];
for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (cell.nodeName.toUpperCase() === 'TH' && !cell.getAttribute('scope')) {
			noScopeTH.push(cell);
		}
	}
}

if (noScopeTH.length) {
	this.relatedNodes(noScopeTH);
	return true;
}

return false;
}},{"id":"th-single-row-column","evaluate":function (node, options) {

var row, cell, position,
	rowHeaders = [],
	columnHeaders = [];

for (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {
	row = node.rows[rowIndex];
	for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
		cell = row.cells[cellIndex];
		if (cell.nodeName) {
			if (commons.table.isColumnHeader(cell) && columnHeaders.indexOf(rowIndex) === -1) {
				columnHeaders.push(rowIndex);
			} else if (commons.table.isRowHeader(cell)) {
				position = commons.table.getCellPosition(cell);
				if (rowHeaders.indexOf(position.x) === -1) {
					rowHeaders.push(position.x);
				}
			}
		}
	}
}

if (columnHeaders.length > 1 || rowHeaders.length > 1) {
	return true;
}

return false;
}}],"commons":(function () {

/*exported commons */
var commons = {};

var aria = commons.aria = {},
	lookupTables = aria._lut = {};

lookupTables.attributes = {
	'aria-activedescendant': {
		type: 'idref'
	},
	'aria-atomic': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-autocomplete': {
		type: 'nmtoken',
		values: ['inline', 'list', 'both', 'none']
	},
	'aria-busy': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-checked': {
		type: 'nmtoken',
		values: ['true', 'false', 'mixed', 'undefined']
	},
	'aria-colcount': {
		type: 'int'
	},
	'aria-colindex': {
		type: 'int'
	},
	'aria-colspan': {
		type: 'int'
	},
	'aria-controls': {
		type: 'idrefs'
	},
	'aria-describedby': {
		type: 'idrefs'
	},
	'aria-disabled': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-dropeffect': {
		type: 'nmtokens',
		values: ['copy', 'move', 'reference', 'execute', 'popup', 'none']
	},
	'aria-expanded': {
		type: 'nmtoken',
		values: ['true', 'false', 'undefined']
	},
	'aria-flowto': {
		type: 'idrefs'
	},
	'aria-grabbed': {
		type: 'nmtoken',
		values: ['true', 'false', 'undefined']
	},
	'aria-haspopup': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-hidden': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-invalid': {
		type: 'nmtoken',
		values: ['true', 'false', 'spelling', 'grammar']
	},
	'aria-label': {
		type: 'string'
	},
	'aria-labelledby': {
		type: 'idrefs'
	},
	'aria-level': {
		type: 'int'
	},
	'aria-live': {
		type: 'nmtoken',
		values: ['off', 'polite', 'assertive']
	},
	'aria-multiline': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-multiselectable': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-orientation' : {
		type : 'nmtoken',
		values : ['horizontal', 'vertical']
	},
	'aria-owns': {
		type: 'idrefs'
	},
	'aria-posinset': {
		type: 'int'
	},
	'aria-pressed': {
		type: 'nmtoken',
		values: ['true', 'false', 'mixed', 'undefined']
	},
	'aria-readonly': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-relevant': {
		type: 'nmtokens',
		values: ['additions', 'removals', 'text', 'all']
	},
	'aria-required': {
		type: 'boolean',
		values: ['true', 'false']
	},
	'aria-rowcount': {
		type: 'int'
	},
	'aria-rowindex': {
		type: 'int'
	},
	'aria-rowspan': {
		type: 'int'
	},
	'aria-selected': {
		type: 'nmtoken',
		values: ['true', 'false', 'undefined']
	},
	'aria-setsize': {
		type: 'int'
	},
	'aria-sort': {
		type: 'nmtoken',
		values: ['ascending', 'descending', 'other', 'none']
	},
	'aria-valuemax': {
		type: 'decimal'
	},
	'aria-valuemin': {
		type: 'decimal'
	},
	'aria-valuenow': {
		type: 'decimal'
	},
	'aria-valuetext': {
		type: 'string'
	}
};

lookupTables.globalAttributes = [
	'aria-atomic', 'aria-busy', 'aria-controls', 'aria-describedby',
	'aria-disabled', 'aria-dropeffect', 'aria-flowto', 'aria-grabbed',
	'aria-haspopup', 'aria-hidden', 'aria-invalid', 'aria-label',
	'aria-labelledby', 'aria-live', 'aria-owns', 'aria-relevant'
];

lookupTables.role = {
	'alert': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'alertdialog': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'application': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'article': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['article']
	},
	'banner': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'button': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded', 'aria-pressed']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null,
		implicit: ['button', 'input[type="button"]', 'input[type="image"]']
	},
	'cell': {
		type: 'structure',
		attributes: {
			allowed: ['aria-colindex', 'aria-colspan', 'aria-rowindex', 'aria-rowspan']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['row']
	},
	'checkbox': {
		type: 'widget',
		attributes:  {
			required: ['aria-checked']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null,
		implicit: ['input[type="checkbox"]']
	},
	'columnheader': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded', 'aria-sort', 'aria-readonly', 'aria-selected', 'aria-required']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['row']
	},
	'combobox': {
		type: 'composite',
		attributes:  {
			required: ['aria-expanded'],
			allowed: ['aria-autocomplete', 'aria-required', 'aria-activedescendant']
		},
		owned: {
			all: ['listbox', 'textbox']
		},
		nameFrom: ['author'],
		context: null
	},
	'command': {
		nameFrom: ['author'],
		type: 'abstract'
	},
	'complementary': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['aside']
	},
	'composite': {
		nameFrom: ['author'],
		type: 'abstract'
	},
	'contentinfo': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'definition': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'dialog': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['dialog']
	},
	'directory': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null
	},
	'document': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['body']
	},
	'form': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'grid': {
		type: 'composite',
		attributes: {
			allowed: ['aria-level', 'aria-multiselectable', 'aria-readonly', 'aria-activedescendant', 'aria-expanded']
		},
		owned: {
			one: ['rowgroup', 'row']
		},
		nameFrom: ['author'],
		context: null
	},
	'gridcell': {
		type: 'widget',
		attributes: {
			allowed: ['aria-selected', 'aria-readonly', 'aria-expanded', 'aria-required']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['row']
	},
	'group': {
		type: 'structure',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['details']
	},
	'heading': {
		type: 'structure',
		attributes: {
			allowed: ['aria-level', 'aria-expanded']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null,
		implicit: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']
	},
	'img': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['img']
	},
	'input': {
		nameFrom: ['author'],
		type: 'abstract'
	},
	'landmark': {
		nameFrom: ['author'],
		type: 'abstract'
	},
	'link': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null,
		implicit: ['a[href]']
	},
	'list': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: {
			all: ['listitem']
		},
		nameFrom: ['author'],
		context: null,
		implicit: ['ol', 'ul']
	},
	'listbox': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-multiselectable', 'aria-required', 'aria-expanded']
		},
		owned: {
			all: ['option']
		},
		nameFrom: ['author'],
		context: null,
		implicit: ['select']
	},
	'listitem': {
		type: 'structure',
		attributes: {
			allowed: ['aria-level', 'aria-posinset', 'aria-setsize', 'aria-expanded']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['list'],
		implicit: ['li']
	},
	'log': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'main': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'marquee': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'math': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'menu': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded']
		},
		owned: {
			one: ['menuitem', 'menuitemradio', 'menuitemcheckbox']
		},
		nameFrom: ['author'],
		context: null
	},
	'menubar': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'menuitem': {
		type: 'widget',
		attributes: null,
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['menu', 'menubar']
	},
	'menuitemcheckbox': {
		type: 'widget',
		attributes: {
			required: ['aria-checked']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['menu', 'menubar']
	},
	'menuitemradio': {
		type: 'widget',
		attributes:  {
			allowed: ['aria-selected', 'aria-posinset', 'aria-setsize'],
			required: ['aria-checked']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['menu', 'menubar']
	},
	'navigation': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'none': {
		type: 'structure',
		attributes: null,
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'note': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'option': {
		type: 'widget',
		attributes: {
			allowed: ['aria-selected', 'aria-posinset', 'aria-setsize', 'aria-checked']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['listbox']
	},
	'presentation': {
		type: 'structure',
		attributes: null,
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'progressbar': {
		type: 'widget',
		attributes: {
			allowed: ['aria-valuetext', 'aria-valuenow', 'aria-valuemax', 'aria-valuemin']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'radio': {
		type: 'widget',
		attributes:  {
			allowed: ['aria-selected', 'aria-posinset', 'aria-setsize'],
			required: ['aria-checked']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null,
		implicit: ['input[type="radio"]']
	},
	'radiogroup': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-required', 'aria-expanded']
		},
		owned: {
			all: ['radio']
		},
		nameFrom: ['author'],
		context: null
	},
	'range': {
		nameFrom: ['author'],
		type: 'abstract'
	},
	'region': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['section']
	},
	'roletype': {
		type: 'abstract'
	},
	'row': {
		type: 'structure',
		attributes: {
			allowed: ['aria-level', 'aria-selected', 'aria-activedescendant', 'aria-expanded']
		},
		owned: {
			one: ['cell', 'columnheader', 'rowheader', 'gridcell']
		},
		nameFrom: ['author', 'contents'],
		context:  ['rowgroup', 'grid', 'treegrid', 'table']
	},
	'rowgroup': {
		type: 'structure',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded']
		},
		owned: {
			all: ['row']
		},
		nameFrom: ['author', 'contents'],
		context:  ['grid', 'table']
	},
	'rowheader': {
		type: 'structure',
		attributes: {
			allowed: ['aria-sort', 'aria-required', 'aria-readonly', 'aria-expanded', 'aria-selected']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['row']
	},
	'scrollbar': {
		type: 'widget',
		attributes: {
			required: ['aria-controls', 'aria-orientation', 'aria-valuenow', 'aria-valuemax', 'aria-valuemin'],
			allowed: ['aria-valuetext']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'search': {
		type: 'landmark',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'searchbox': {
		type: 'widget',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-autocomplete', 'aria-multiline', 'aria-readonly', 'aria-required']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['input[type="search"]']
	},
	'section': {
		nameFrom: ['author', 'contents'],
		type: 'abstract'
	},
	'sectionhead': {
		nameFrom: ['author', 'contents'],
		type: 'abstract'
	},
	'select': {
		nameFrom: ['author'],
		type: 'abstract'
	},
	'separator': {
		type: 'structure',
		attributes: {
			allowed: ['aria-expanded', 'aria-orientation']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'slider': {
		type: 'widget',
		attributes: {
			allowed: ['aria-valuetext', 'aria-orientation'],
			required: ['aria-valuenow', 'aria-valuemax', 'aria-valuemin']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'spinbutton': {
		type: 'widget',
		attributes: {
			allowed: ['aria-valuetext', 'aria-required'],
			required: ['aria-valuenow', 'aria-valuemax', 'aria-valuemin']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'status': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['output']
	},
	'structure': {
		type: 'abstract'
	},
	'switch': {
		type: 'widget',
		attributes:  {
			required: ['aria-checked']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null
	},
	'tab': {
		type: 'widget',
		attributes: {
			allowed: ['aria-selected', 'aria-expanded']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['tablist']
	},
	'table': {
		type: 'structure',
		attributes: {
			allowed: ['aria-colcount', 'aria-rowcount']
		},
		owned: {
			one: ['rowgroup', 'row']
		},
		nameFrom: ['author'],
		context: null,
		implicit: ['table']
	},
	'tablist': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded', 'aria-level', 'aria-multiselectable']
		},
		owned: {
			all: ['tab']
		},
		nameFrom: ['author'],
		context: null
	},
	'tabpanel': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'text': {
		type: 'structure',
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null
	},
	'textbox': {
		type: 'widget',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-autocomplete', 'aria-multiline', 'aria-readonly', 'aria-required']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['input[type="text"]', 'input:not([type])']
	},
	'timer': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null
	},
	'toolbar': {
		type: 'structure',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded']
		},
		owned: null,
		nameFrom: ['author'],
		context: null,
		implicit: ['menu[type="toolbar"]']
	},
	'tooltip': {
		type: 'widget',
		attributes: {
			allowed: ['aria-expanded']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: null
	},
	'tree': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-multiselectable', 'aria-required', 'aria-expanded']
		},
		owned: {
			all: ['treeitem']
		},
		nameFrom: ['author'],
		context: null
	},
	'treegrid': {
		type: 'composite',
		attributes: {
			allowed: ['aria-activedescendant', 'aria-expanded', 'aria-level', 'aria-multiselectable',
				'aria-readonly', 'aria-required']
		},
		owned: {
			all: ['treeitem']
		},
		nameFrom: ['author'],
		context: null
	},
	'treeitem': {
		type: 'widget',
		attributes: {
			allowed: ['aria-checked', 'aria-selected', 'aria-expanded', 'aria-level', 'aria-posinset', 'aria-setsize']
		},
		owned: null,
		nameFrom: ['author', 'contents'],
		context: ['treegrid', 'tree']
	},
	'widget': {
		type: 'abstract'
	},
	'window': {
		nameFrom: ['author'],
		type: 'abstract'
	}
};

var color = {};
commons.color = color;

/*exported dom */
var dom = commons.dom = {};

/*exported table */
var table = commons.table = {};

/*exported text */
var text = commons.text = {};
/*exported utils */
/*global axe */
var utils = commons.utils = {};

utils.escapeSelector = axe.utils.escapeSelector;
utils.matchesSelector = axe.utils.matchesSelector;
utils.clone = axe.utils.clone;

/*global aria, utils, lookupTables */

/**
 * Get required attributes for a given role
 * @param  {String} role The role to check
 * @return {Array}
 */
aria.requiredAttr = function (role) {
	'use strict';
	var roles = lookupTables.role[role],
		attr = roles && roles.attributes && roles.attributes.required;
	return attr || [];
};

/**
 * Get allowed attributes for a given role
 * @param  {String} role The role to check
 * @return {Array}
 */
aria.allowedAttr = function (role) {
	'use strict';
	var roles = lookupTables.role[role],
		attr = (roles && roles.attributes && roles.attributes.allowed) || [],
		requiredAttr = (roles && roles.attributes && roles.attributes.required) || [];
	return attr.concat(lookupTables.globalAttributes).concat(requiredAttr);
};

/**
 * Check if an aria- attribute name is valid
 * @param  {String} att The attribute name
 * @return {Boolean}
 */
aria.validateAttr = function (att) {
	'use strict';
	return !!lookupTables.attributes[att];
};

/**
 * Validate the value of an ARIA attribute
 * @param  {HTMLElement} node The element to check
 * @param  {String} attr The name of the attribute
 * @return {Boolean}
 */
aria.validateAttrValue = function (node, attr) {
	//jshint maxcomplexity: 12
	'use strict';
	var ids, index, length, matches,
		doc = document,
		value = node.getAttribute(attr),
		attrInfo = lookupTables.attributes[attr];

	if (!attrInfo) {
		return true;

	} else if (attrInfo.values) {
		if (typeof value === 'string' && attrInfo.values.indexOf(value.toLowerCase()) !== -1) {
			return true;
		}
		return false;
	}

	switch (attrInfo.type) {
	case 'idref':
		return !!(value && doc.getElementById(value));

	case 'idrefs':
		ids = utils.tokenList(value);
		for (index = 0, length = ids.length; index < length; index++) {
			if (ids[index] && !doc.getElementById(ids[index])) {
				return false;
			}
		}
		// not valid if there are no elements
		return !!ids.length;

	case 'string':
		// anything goes
		return true;

	case 'decimal':
		matches = value.match(/^[-+]?([0-9]*)\.?([0-9]*)$/);
		return !!(matches && (matches[1] || matches[2]));

	case 'int':
		return (/^[-+]?[0-9]+$/).test(value);
	}
};

/*global aria, dom, text */
/**
 * Gets the accessible ARIA label text of a given element
 * @see http://www.w3.org/WAI/PF/aria/roles#namecalculation
 * @param  {HTMLElement} node The element to test
 * @return {Mixed}      String of visible text, or `null` if no label is found
 */
aria.label = function (node) {
	var ref, candidate;

	if (node.getAttribute('aria-labelledby')) {
		// aria-labelledby
		ref = dom.idrefs(node, 'aria-labelledby');
		candidate = ref.map(function (thing) {
			return thing ? text.visible(thing, true) : '';
		}).join(' ').trim();

		if (candidate) {
			return candidate;
		}
	}

	// aria-label
	candidate = node.getAttribute('aria-label');
	if (candidate) {
		candidate = text.sanitize(candidate).trim();
		if (candidate) {
			return candidate;
		}
	}

	return null;
};

/*global aria, lookupTables, utils */

/**
 * Check if a given role is valid
 * @param  {String}  role The role to check
 * @return {Boolean}
 */
aria.isValidRole = function (role) {
	'use strict';
	if (lookupTables.role[role]) {
		return true;
	}

	return false;
};

/**
 * Get the roles that get name from contents
 * @return {Array}           Array of roles that match the type
 */
aria.getRolesWithNameFromContents = function () {
	return Object.keys(lookupTables.role).filter(function (r) {
		return lookupTables.role[r].nameFrom &&
			lookupTables.role[r].nameFrom.indexOf('contents') !== -1;
	});
};

/**
 * Get the roles that have a certain "type"
 * @param  {String} roleType The roletype to check
 * @return {Array}           Array of roles that match the type
 */
aria.getRolesByType = function (roleType) {
	return Object.keys(lookupTables.role).filter(function (r) {
		return lookupTables.role[r].type === roleType;
	});
};

/**
 * Get the "type" of role; either widget, composite, abstract, landmark or `null`
 * @param  {String} role The role to check
 * @return {Mixed}       String if a matching role and its type are found, otherwise `null`
 */
aria.getRoleType = function (role) {
	var r = lookupTables.role[role];

	return (r && r.type) || null;
};

/**
 * Get the required owned (children) roles for a given role
 * @param  {String} role The role to check
 * @return {Mixed}       Either an Array of required owned elements or `null` if there are none
 */
aria.requiredOwned = function (role) {
	'use strict';
	var owned = null,
		roles = lookupTables.role[role];

	if (roles) {
		owned = utils.clone(roles.owned);
	}
	return owned;
};

/**
 * Get the required context (parent) roles for a given role
 * @param  {String} role The role to check
 * @return {Mixed}       Either an Array of required context elements or `null` if there are none
 */
aria.requiredContext = function (role) {
	'use strict';
	var context = null,
		roles = lookupTables.role[role];

	if (roles) {
		context = utils.clone(roles.context);
	}
	return context;
};

/**
 * Get a list of CSS selectors of nodes that have an implicit role
 * @param  {String} role The role to check
 * @return {Mixed}       Either an Array of CSS selectors or `null` if there are none
 */
aria.implicitNodes = function (role) {
	'use strict';

	var implicit = null,
		roles = lookupTables.role[role];

	if (roles && roles.implicit) {
		implicit = utils.clone(roles.implicit);
	}
	return implicit;
};

/**
 * Get the implicit role for a given node
 * @param  {HTMLElement} node The node to test
 * @return {Mixed}      Either the role or `null` if there is none
 */
aria.implicitRole = function (node) {
	'use strict';

	var role, r, candidate,
		roles = lookupTables.role;

	for (role in roles) {
		if (roles.hasOwnProperty(role)) {
			r = roles[role];
			if (r.implicit) {
				for (var index = 0, length = r.implicit.length; index < length; index++) {
					candidate = r.implicit[index];
					if (utils.matchesSelector(node, candidate)) {
						return role;
					}
				}
			}
		}
	}

	return null;
};

/*global color */

/**
 * @constructor
 * @param {number} red
 * @param {number} green
 * @param {number} blue
 * @param {number} alpha
 */
color.Color = function (red, green, blue, alpha) {
	/** @type {number} */
	this.red = red;

	/** @type {number} */
	this.green = green;

	/** @type {number} */
	this.blue = blue;

	/** @type {number} */
	this.alpha = alpha;

	/**
	 * Provide the hex string value for the color
	 * @return {string}
	 */
	this.toHexString = function () {
		var redString = Math.round(this.red).toString(16);
		var greenString = Math.round(this.green).toString(16);
		var blueString = Math.round(this.blue).toString(16);
		return '#' + (this.red > 15.5 ? redString : '0' + redString) +
			(this.green > 15.5 ? greenString : '0' + greenString) +
			(this.blue > 15.5 ? blueString : '0' + blueString);
	};
	
	var rgbRegex = /^rgb\((\d+), (\d+), (\d+)\)$/;
	var rgbaRegex = /^rgba\((\d+), (\d+), (\d+), (\d*(\.\d+)?)\)/;

	/** 
	 * Set the color value based on a CSS RGB/RGBA string
	 * @param  {string}  rgb  The string value
	 */
	this.parseRgbString = function (colorString) {
		var match = colorString.match(rgbRegex);

		if (match) {
			this.red = parseInt(match[1], 10);
			this.green = parseInt(match[2], 10);
			this.blue = parseInt(match[3], 10);
			this.alpha = 1;
			return;
		}

		match = colorString.match(rgbaRegex);
		if (match) {
			this.red = parseInt(match[1], 10);
			this.green = parseInt(match[2], 10);
			this.blue = parseInt(match[3], 10);
			this.alpha = parseFloat(match[4]);
			return;
		}
	};

	/**
	 * Get the relative luminance value
	 * using algorithm from http://www.w3.org/WAI/GL/wiki/Relative_luminance
	 * @return {number} The luminance value, ranges from 0 to 1
	 */
	this.getRelativeLuminance = function () {
		var rSRGB = this.red / 255;
		var gSRGB = this.green / 255;
		var bSRGB = this.blue / 255;

		var r = rSRGB <= 0.03928 ? rSRGB / 12.92 : Math.pow(((rSRGB + 0.055) / 1.055), 2.4);
		var g = gSRGB <= 0.03928 ? gSRGB / 12.92 : Math.pow(((gSRGB + 0.055) / 1.055), 2.4);
		var b = bSRGB <= 0.03928 ? bSRGB / 12.92 : Math.pow(((bSRGB + 0.055) / 1.055), 2.4);

		return 0.2126 * r + 0.7152 * g + 0.0722 * b;
	};
};

/**
 * Combine the two given color according to alpha blending.
 * @param {Color} fgColor
 * @param {Color} bgColor
 * @return {Color}
 */
color.flattenColors = function (fgColor, bgColor) {
	var alpha = fgColor.alpha;
	var r = ((1 - alpha) * bgColor.red) + (alpha * fgColor.red);
	var g  = ((1 - alpha) * bgColor.green) + (alpha * fgColor.green);
	var b = ((1 - alpha) * bgColor.blue) + (alpha * fgColor.blue);
	var a = fgColor.alpha + (bgColor.alpha * (1 - fgColor.alpha));

	return new color.Color(r, g, b, a);
};

/**
 * Get the contrast of two colors
 * @param  {Color}  bgcolor  Background color
 * @param  {Color}  fgcolor  Foreground color
 * @return {number} The contrast ratio
 */
color.getContrast = function (bgColor, fgColor) {
	if (!fgColor || !bgColor) { return null; }

	if (fgColor.alpha < 1) {
		fgColor = color.flattenColors(fgColor, bgColor);
	}

	var bL = bgColor.getRelativeLuminance();
	var fL = fgColor.getRelativeLuminance();

	return (Math.max(fL, bL) + 0.05) / (Math.min(fL, bL) + 0.05);
};

/**
 * Check whether certain text properties meet WCAG contrast rules
 * @param  {Color}  bgcolor  Background color
 * @param  {Color}  fgcolor  Foreground color
 * @param  {number}  fontSize  Font size of text, in pixels
 * @param  {boolean}  isBold  Whether the text is bold
 * @return {{isValid: boolean, contrastRatio: number}} 
 */
color.hasValidContrastRatio = function (bg, fg, fontSize, isBold) {
	var contrast = color.getContrast(bg, fg);
	var isSmallFont = (isBold && (Math.ceil(fontSize * 72) / 96) < 14) || (!isBold && (Math.ceil(fontSize * 72) / 96) < 18);

	return {
		isValid: (isSmallFont && contrast >= 4.5) || (!isSmallFont && contrast >= 3),
		contrastRatio: contrast
	};

};

/*global dom, color */
/* jshint maxstatements: 32, maxcomplexity: 15 */
//TODO dsturley: too complex, needs refactor!!

/**
 * Returns the non-alpha-blended background color of a node, null if it's an image
 * @param {Element} node
 * @return {Color}
 */
function getBackgroundForSingleNode(node) {
	var bgColor,
		nodeStyle = window.getComputedStyle(node);

	if (nodeStyle.getPropertyValue('background-image') !== 'none') {
		return null;
	}

	var bgColorString = nodeStyle.getPropertyValue('background-color');
	//Firefox exposes unspecified background as 'transparent' rather than rgba(0,0,0,0)
	if (bgColorString === 'transparent') {
		bgColor = new color.Color(0, 0, 0, 0);
	} else {
		bgColor = new color.Color();
		bgColor.parseRgbString(bgColorString);
	}
	var opacity = nodeStyle.getPropertyValue('opacity');
	bgColor.alpha = bgColor.alpha * opacity;

	return bgColor;
}

/**
 * Determines whether an element has a fully opaque background, whether solid color or an image
 * @param {Element} node
 * @return {Boolean} false if the background is transparent, true otherwise
 */
dom.isOpaque = function(node) {
	var bgColor = getBackgroundForSingleNode(node);
	if (bgColor === null || bgColor.alpha === 1) {
		return true;
	}
	return false;
};

/**
 * Returns the elements that are visually "above" this one in z-index order where
 * supported at the position given inside the top-left corner of the provided
 * rectangle. Where not supported (IE < 10), returns the DOM parents.
 * @param {Element} node
 * @param {DOMRect} rect rectangle containing dimensions to consider
 * @return {Array} array of elements
 */
var getVisualParents = function(node, rect) {
	var visualParents,
		thisIndex,
		parents = [],
		fallbackToVisual = false,
		currentNode = node,
		nodeStyle = window.getComputedStyle(currentNode),
		posVal, topVal, bottomVal, leftVal, rightVal;

	while (currentNode !== null && (!dom.isOpaque(currentNode) || parseInt(nodeStyle.getPropertyValue('height'), 10) === 0)) {
		// If the element is positioned, we can't rely on DOM order to find visual parents
		posVal = nodeStyle.getPropertyValue('position');
		topVal = nodeStyle.getPropertyValue('top');
		bottomVal = nodeStyle.getPropertyValue('bottom');
		leftVal = nodeStyle.getPropertyValue('left');
		rightVal = nodeStyle.getPropertyValue('right');
		if ((posVal !== 'static' && posVal !== 'relative') ||
			(posVal === 'relative' &&
				(leftVal !== 'auto' ||
					rightVal !== 'auto' ||
					topVal !== 'auto' ||
					bottomVal !== 'auto'))) {
			fallbackToVisual = true;
		}
		currentNode = currentNode.parentElement;
		if (currentNode !== null) {
			nodeStyle = window.getComputedStyle(currentNode);
			if (parseInt(nodeStyle.getPropertyValue('height'), 10) !== 0) {
				parents.push(currentNode);
			}
		}
	}

	if (fallbackToVisual && dom.supportsElementsFromPoint(document)) {
		visualParents = dom.elementsFromPoint(document,
			Math.ceil(rect.left + 1),
			Math.ceil(rect.top + 1));
		thisIndex = visualParents.indexOf(node);

		// if the element is not present; then something is obscuring it thus making calculation impossible
		if (thisIndex === -1) {
			return null;
		}

		if (visualParents && (thisIndex < visualParents.length - 1)) {
			parents = visualParents.slice(thisIndex + 1);
		}
	}

	return parents;
};


/**
 * Returns the flattened background color of an element, or null if it can't be determined because
 * there is no opaque ancestor element visually containing it, or because background images are used.
 * @param {Element} node
 * @param {Array} bgNodes array to which all encountered nodes should be appended
 * @param {Boolean} useScroll
 * @return {Color}
 */
//TODO dsturley; why is this passing `bgNodes`?
color.getBackgroundColor = function(node, bgNodes, useScroll) {
	var parent, parentColor;

	var bgColor = getBackgroundForSingleNode(node);
	if (bgNodes && (bgColor === null || bgColor.alpha !== 0)) {
		bgNodes.push(node);
	}
	if (bgColor === null || bgColor.alpha === 1) {
		return bgColor;
	}

	if(useScroll) {
		node.scrollIntoView();
	}

	var rect = node.getBoundingClientRect(),
		currentNode = node,
		colorStack = [{
			color: bgColor,
			node: node
		}],
		parents = getVisualParents(currentNode, rect);
	if (!parents) {
		return null;
	}

	while (bgColor.alpha !== 1) {
		parent = parents.shift();

		if (!parent && currentNode.tagName !== 'HTML') {
			return null;
		}

		//Assume white if top level is not specified
		if (!parent && currentNode.tagName === 'HTML') {
			parentColor = new color.Color(255, 255, 255, 1);
		} else {

			if (!dom.visuallyContains(node, parent)) {
				return null;
			}

			parentColor = getBackgroundForSingleNode(parent);
			if (bgNodes && (parentColor === null || parentColor.alpha !== 0)) {
				bgNodes.push(parent);
			}
			if (parentColor === null) {
				return null;
			}
		}
		currentNode = parent;
		bgColor = parentColor;
		colorStack.push({
			color: bgColor,
			node: currentNode
		});
	}

	var currColorNode = colorStack.pop();
	var flattenedColor = currColorNode.color;

	while ((currColorNode = colorStack.pop()) !== undefined) {
		flattenedColor = color.flattenColors(currColorNode.color, flattenedColor);
	}

	return flattenedColor;
};

/*global color */

/**
 * Returns the flattened foreground color of an element, or null if it can't be determined because
 * of transparency
 * @param {Element} node
 * @param {Boolean} useScroll
 * @return {Color}
 */
color.getForegroundColor = function (node, useScroll) {
	var nodeStyle = window.getComputedStyle(node);

	var fgColor = new color.Color();
	fgColor.parseRgbString(nodeStyle.getPropertyValue('color'));
	var opacity = nodeStyle.getPropertyValue('opacity');
	fgColor.alpha = fgColor.alpha * opacity;
	if (fgColor.alpha === 1) { return fgColor; }

	var bgColor = color.getBackgroundColor(node, [], useScroll);
	if (bgColor === null) { return null; }

	return color.flattenColors(fgColor, bgColor);
};

/* global dom */

/**
 * Returns true if the browser supports one of the methods to get elements from point
 * @param {Document} doc The HTML document
 * @return {Boolean}
 */
dom.supportsElementsFromPoint = function (doc) {
	var element = doc.createElement('x');
	element.style.cssText = 'pointer-events:auto';
	return element.style.pointerEvents === 'auto' || !!doc.msElementsFromPoint;
};


/**
 * Returns the elements at a particular point in the viewport, in z-index order
 * @param {Document} doc The HTML document
 * @param {Element} x The x coordinate, as an integer
 * @param {Element} y The y coordinate, as an integer
 * @return {Array} Array of Elements
 */
dom.elementsFromPoint = function (doc, x, y) {
	var elements = [], previousPointerEvents = [], current, i, d;

	if (doc.msElementsFromPoint) {
		var nl = doc.msElementsFromPoint(x, y);
		return nl ? Array.prototype.slice.call(nl) : null;
	}

	// get all elements via elementFromPoint, and remove them from hit-testing in order
	while ((current = doc.elementFromPoint(x, y)) && elements.indexOf(current) === -1 && current !== null) {

		// push the element and its current style
		elements.push(current);

		previousPointerEvents.push({
			value: current.style.getPropertyValue('pointer-events'),
			priority: current.style.getPropertyPriority('pointer-events')
		});

		// add "pointer-events: none", to get to the underlying element
		current.style.setProperty('pointer-events', 'none', 'important');

		if (dom.isOpaque(current)) { break; }
	}

	// restore the previous pointer-events values
	for (i = previousPointerEvents.length; !!(d = previousPointerEvents[--i]);) {
		elements[i].style.setProperty('pointer-events', d.value ? d.value : '', d.priority);
	}

	// return our results
	return elements;
};

/*global dom, utils */
/**
 * recusively walk up the DOM, checking for a node which matches a selector
 *
 * **WARNING:** this should be used sparingly, as it's not even close to being performant
 *
 * @param {HTMLElement|String} element The starting HTMLElement
 * @param {String} selector The selector for the HTMLElement
 * @return {HTMLElement|null} Either the matching HTMLElement or `null` if there was no match
 */
dom.findUp = function (element, target) {
	'use strict';
	/*jslint browser:true*/

	var parent,
		matches = document.querySelectorAll(target),
		length = matches.length;

	if (!length) {
		return null;
	}

	matches = utils.toArray(matches);

	parent = element.parentNode;
	// recrusively walk up the DOM, checking each parent node
	while (parent && matches.indexOf(parent) === -1) {
		parent = parent.parentNode;
	}

	return parent;
};

/*global dom */

dom.getElementByReference = function (node, attr) {
	'use strict';

	var candidate,
		fragment = node.getAttribute(attr),
		doc = document;

	if (fragment && fragment.charAt(0) === '#') {
		fragment = fragment.substring(1);

		candidate = doc.getElementById(fragment);
		if (candidate) {
			return candidate;
		}

		candidate = doc.getElementsByName(fragment);
		if (candidate.length) {
			return candidate[0];
		}

	}

	return null;
};
/*global dom */
/**
 * Get the coordinates of the element passed into the function relative to the document
 *
 * #### Returns
 *
 * Returns a `Object` with the following properties, which
 * each hold a value representing the pixels for each of the
 * respective coordinates:
 *
 * - `top`
 * - `right`
 * - `bottom`
 * - `left`
 * - `width`
 * - `height`
 *
 * @param {HTMLElement} el The HTMLElement
 */
dom.getElementCoordinates = function (element) {
	'use strict';

	var scrollOffset = dom.getScrollOffset(document),
		xOffset = scrollOffset.left,
		yOffset = scrollOffset.top,
		coords = element.getBoundingClientRect();

	return {
		top: coords.top + yOffset,
		right: coords.right + xOffset,
		bottom: coords.bottom + yOffset,
		left: coords.left + xOffset,

		width: coords.right - coords.left,
		height: coords.bottom - coords.top
	};
};

/*global dom */
/**
 * Get the scroll offset of the document passed in
 *
 * @param {Document} element The element to evaluate, defaults to document
 * @return {Object} Contains the attributes `x` and `y` which contain the scroll offsets
 */
dom.getScrollOffset = function (element) {
	'use strict';

	if (!element.nodeType && element.document) {
		element = element.document;
	}

	// 9 === Node.DOCUMENT_NODE
	if (element.nodeType === 9) {
		var docElement = element.documentElement,
			body = element.body;

		return {
			left: (docElement && docElement.scrollLeft || body && body.scrollLeft || 0),
			top: (docElement && docElement.scrollTop || body && body.scrollTop || 0)
		};
	}

	return {
		left: element.scrollLeft,
		top: element.scrollTop
	};
};
/*global dom */
/**
 * Gets the width and height of the viewport; used to calculate the right and bottom boundaries of the viewable area.
 *
 * @api private
 * @param  {Object}  window The `window` object that should be measured
 * @return {Object}  Object with the `width` and `height` of the viewport
 */
dom.getViewportSize = function (win) {
	'use strict';

	var body,
		doc = win.document,
		docElement = doc.documentElement;

	if (win.innerWidth) {
		return {
			width: win.innerWidth,
			height: win.innerHeight
		};
	}

	if (docElement) {
		return {
			width: docElement.clientWidth,
			height: docElement.clientHeight
		};

	}

	body = doc.body;

	return {
		width: body.clientWidth,
		height: body.clientHeight
	};
};
/*global dom, utils */

/**
 * Get elements referenced via a space-separated token attribute; it will insert `null` for any Element that is not found
 * @param  {HTMLElement} node
 * @param  {String} attr The name of attribute
 * @return {Array}      Array of elements (or `null` if not found)
 */
dom.idrefs = function (node, attr) {
	'use strict';

	var index, length,
		doc = document,
		result = [],
		idrefs = node.getAttribute(attr);

	if (idrefs) {
		idrefs = utils.tokenList(idrefs);
		for (index = 0, length = idrefs.length; index < length; index++) {
			result.push(doc.getElementById(idrefs[index]));
		}
	}

	return result;
};
/*global dom */
/* jshint maxcomplexity: 20 */
/**
 * Determines if an element is focusable
 * @param {HTMLelement} element The HTMLelement
 * @return {Boolean} The element's focusability status
 */

dom.isFocusable = function (el) {
	'use strict';

	if (!el ||
		el.disabled ||
		(!dom.isVisible(el) && el.nodeName.toUpperCase() !== 'AREA')) {
		return false;
	}

	switch (el.nodeName.toUpperCase()) {
		case 'A':
		case 'AREA':
			if (el.href) {
				return true;
			}
			break;
		case 'INPUT':
			return el.type !== 'hidden';
		case 'TEXTAREA':
		case 'SELECT':
		case 'DETAILS':
		case 'BUTTON':
			return true;
	}

	// check if the tabindex is specified and a parseable number
	var tabindex = el.getAttribute('tabindex');
	if (tabindex && !isNaN(parseInt(tabindex, 10))) {
		return true;
	}

	return false;
};

/*global dom */
dom.isHTML5 = function (doc) {
	var node = doc.doctype;
	if (node === null) {
		return false;
	}
	return node.name === 'html' && !node.publicId && !node.systemId;
};
/*global dom */
dom.isNode = function (candidate) {
	'use strict';
	return candidate instanceof Node;
};

/*global dom */

dom.isOffscreen = function (element) {
	'use strict';

	var leftBoundary,
		docElement = document.documentElement,
		dir = window.getComputedStyle(document.body || docElement)
			.getPropertyValue('direction'),
		coords = dom.getElementCoordinates(element);

	// bottom edge beyond
	if (coords.bottom < 0) {
		return true;
	}

	if (dir === 'ltr') {
		if (coords.right < 0) {
			return true;
		}
	} else {

		leftBoundary = Math.max(docElement.scrollWidth, dom.getViewportSize(window).width);
		if (coords.left > leftBoundary) {
			return true;
		}
	}

	return false;

};

/*global dom */
/*jshint maxcomplexity: 11 */

/**
 * Determines if an element is hidden with the clip rect technique
 * @param  {String}  clip Computed property value of clip
 * @return {Boolean}
 */
function isClipped(clip) {
	'use strict';

	var matches = clip.match(/rect\s*\(([0-9]+)px,?\s*([0-9]+)px,?\s*([0-9]+)px,?\s*([0-9]+)px\s*\)/);
	if (matches && matches.length === 5) {
		return matches[3] - matches[1] <= 0 && matches[2] - matches[4] <= 0;
	}

	return false;

}

/**
 * Determine whether an element is visible
 *
 * @param {HTMLElement} el The HTMLElement
 * @param {Boolean} screenReader When provided, will evaluate visibility from the perspective of a screen reader
 * @return {Boolean} The element's visibilty status
 */
dom.isVisible = function (el, screenReader, recursed) {
	'use strict';
	var style,
		nodeName = el.nodeName,
		parent = el.parentNode;

	// 9 === Node.DOCUMENT
	if (el.nodeType === 9) {
		return true;
	}

	style = window.getComputedStyle(el, null);
	if (style === null) {
		return false;
	}

	if (style.getPropertyValue('display') === 'none' ||

		nodeName.toUpperCase() === 'STYLE' || nodeName.toUpperCase() === 'SCRIPT' ||

		(!screenReader && (isClipped(style.getPropertyValue('clip')))) ||

		(!recursed &&
			// visibility is only accurate on the first element
			(style.getPropertyValue('visibility') === 'hidden' ||
			// position does not matter if it was already calculated
			!screenReader && dom.isOffscreen(el))) ||

		(screenReader && el.getAttribute('aria-hidden') === 'true')) {

		return false;
	}

	if (parent) {
		return dom.isVisible(parent, screenReader, true);
	}

	return false;

};

/*global dom */
/*jshint maxcomplexity: 20 */

/**
 * Check if an element is an inherently visual element
 * @param  {object}  candidate The node to check
 * @return {Boolean}
 */
dom.isVisualContent = function (candidate) {
	'use strict';
	switch (candidate.tagName.toUpperCase()) {
		case 'IMG':
		case 'IFRAME':
		case 'OBJECT':
		case 'VIDEO':
		case 'AUDIO':
		case 'CANVAS':
		case 'SVG':
		case 'MATH':
		case 'BUTTON':
		case 'SELECT':
		case 'TEXTAREA':
		case 'KEYGEN':
		case 'PROGRESS':
		case 'METER':
			return true;
		case 'INPUT':
			return candidate.type !== 'hidden';
		default:
			return false;
	}

};

/* global dom */
/* jshint maxcomplexity: 11 */

/**
 * Checks whether a parent element visually contains its child, either directly or via scrolling.
 * Assumes that |parent| is an ancestor of |node|.
 * @param {Element} node
 * @param {Element} parent
 * @return {boolean} True if node is visually contained within parent
 */
dom.visuallyContains = function (node, parent) {
	var rect = node.getBoundingClientRect();
	var parentRect = parent.getBoundingClientRect();
	var parentTop = parentRect.top;
	var parentLeft = parentRect.left;
	var parentScrollArea = {
		top: parentTop - parent.scrollTop,
		bottom: parentTop - parent.scrollTop + parent.scrollHeight,
		left: parentLeft - parent.scrollLeft,
		right: parentLeft - parent.scrollLeft + parent.scrollWidth
	};

	//In theory, we should just be able to look at the scroll area as a superset of the parentRect,
	//but that's not true in Firefox
	if ((rect.left < parentScrollArea.left && rect.left < parentRect.left) ||
		(rect.top < parentScrollArea.top && rect.top < parentRect.top) ||
		(rect.right > parentScrollArea.right && rect.right > parentRect.right) ||
		(rect.bottom > parentScrollArea.bottom && rect.bottom > parentRect.bottom)) {
		return false;
	}

	var style = window.getComputedStyle(parent);

	if (rect.right > parentRect.right || rect.bottom > parentRect.bottom) {
		return (style.overflow === 'scroll' || style.overflow === 'auto' ||
				style.overflow === 'hidden' || parent instanceof HTMLBodyElement ||
				parent instanceof HTMLHtmlElement);
	}

	return true;
};

/* global dom */
/* jshint maxcomplexity: 11 */

/**
 * Checks whether a parent element visually overlaps a rectangle, either directly or via scrolling.
 * @param {DOMRect} rect
 * @param {Element} parent
 * @return {boolean} True if rect is visually contained within parent
 */
dom.visuallyOverlaps = function (rect, parent) {
	var parentRect = parent.getBoundingClientRect();
	var parentTop = parentRect.top;
	var parentLeft = parentRect.left;
	var parentScrollArea = {
		top: parentTop - parent.scrollTop,
		bottom: parentTop - parent.scrollTop + parent.scrollHeight,
		left: parentLeft - parent.scrollLeft,
		right: parentLeft - parent.scrollLeft + parent.scrollWidth
	};

	//In theory, we should just be able to look at the scroll area as a superset of the parentRect,
	//but that's not true in Firefox
	if ((rect.left > parentScrollArea.right && rect.left > parentRect.right) ||
		(rect.top > parentScrollArea.bottom && rect.top > parentRect.bottom) ||
		(rect.right < parentScrollArea.left && rect.right < parentRect.left) ||
		(rect.bottom < parentScrollArea.top && rect.bottom < parentRect.top)) {
		return false;
	}

	var style = window.getComputedStyle(parent);

	if (rect.left > parentRect.right || rect.top > parentRect.bottom) {
		return (style.overflow === 'scroll' || style.overflow === 'auto' ||
				parent instanceof HTMLBodyElement ||
				parent instanceof HTMLHtmlElement);
	}

	return true;
};

/*global table, dom */

/**
 * Get the x, y coordinates of a table cell; normalized for rowspan and colspan
 * @param  {HTMLTableCelLElement} cell The table cell of which to get the position
 * @return {Object}      Object with `x` and `y` properties of the coordinates
 */
table.getCellPosition = function (cell) {

	var tbl = table.toArray(dom.findUp(cell, 'table')),
		index;

	for (var rowIndex = 0; rowIndex < tbl.length; rowIndex++) {
		if (tbl[rowIndex]) {
			index = tbl[rowIndex].indexOf(cell);
			if (index !== -1) {
				return {
					x: index,
					y: rowIndex
				};
			}
		}
	}

};
/*global table */

/**
 * Get any associated table headers for a `HTMLTableCellElement`
 * @param  {HTMLTableCellElement} cell The cell of which to get headers
 * @return {Array}      Array of headers associated to the table cell
 */
table.getHeaders = function (cell) {

	if (cell.getAttribute('headers')) {
		return commons.dom.idrefs(cell, 'headers');
	}

	var headers = [], currentCell,
		tbl = commons.table.toArray(commons.dom.findUp(cell, 'table')),
		position = commons.table.getCellPosition(cell);

	//
	for (var x = position.x - 1; x >= 0; x--) {
		currentCell = tbl[position.y][x];

		if (commons.table.isRowHeader(currentCell)) {
			headers.unshift(currentCell);
		}
	}

	for (var y = position.y - 1; y >= 0; y--) {
		currentCell = tbl[y][position.x];

		if (currentCell && commons.table.isColumnHeader(currentCell)) {
			headers.unshift(currentCell);
		}
	}

	return headers;

};
/*global table, dom */

/**
 * Determine if a `HTMLTableCellElement` is a column header
 * @param  {HTMLTableCellElement}  node The table cell to test
 * @return {Boolean}
 */
table.isColumnHeader = function (node) {

	var scope = node.getAttribute('scope');
	if (scope === 'col') {
		return true;
	} else if (scope || node.nodeName.toUpperCase() !== 'TH') {
		return false;
	}

	var currentCell,
		position = table.getCellPosition(node),
		tbl = table.toArray(dom.findUp(node, 'table')),
		cells = tbl[position.y];

	for (var cellIndex = 0, cellLength = cells.length; cellIndex < cellLength; cellIndex++) {
		currentCell = cells[cellIndex];
		if (currentCell !== node) {
			if (table.isDataCell(currentCell)) {
				return false;
			}
		}
	}

	return true;

};
/*global table */

/**
 * Determine if a `HTMLTableCellElement` is a data cell
 * @param  {HTMLTableCellElement}  node The table cell to test
 * @return {Boolean}
 */
table.isDataCell = function (cell) {
	// @see http://www.whatwg.org/specs/web-apps/current-work/multipage/tables.html#empty-cell
	if (!cell.children.length && !cell.textContent.trim()) {
		return false;
	}
	return cell.nodeName.toUpperCase() === 'TD';
};
/*global table, dom */
/*jshint maxstatements: 65, maxcomplexity: 37 */

/**
 * Determines whether a table is a data table
 * @param  {HTMLTableElement}  node The table to test
 * @return {Boolean}
 * @see http://asurkov.blogspot.co.uk/2011/10/data-vs-layout-table.html
 */
table.isDataTable = function (node) {

	var role = node.getAttribute('role');

	// The element is not focusable and has role=presentation
	if ((role === 'presentation' || role === 'none') && !dom.isFocusable(node)) {
		return false;
	}

	// Table inside editable area is data table always since the table structure is crucial for table editing
	if (node.getAttribute('contenteditable') === 'true' || dom.findUp(node, '[contenteditable="true"]')) {
		return true;
	}

	// Table having ARIA table related role is data table
	if (role === 'grid' || role === 'treegrid' || role === 'table') {
		return true;
	}

	// Table having ARIA landmark role is data table
	if (commons.aria.getRoleType(role) === 'landmark') {
		return true;
	}

	// Table having datatable="0" attribute is layout table
	if (node.getAttribute('datatable') === '0') {
		return false;
	}

	// Table having summary attribute is data table
	if (node.getAttribute('summary')) {
		return true;

	}

	// Table having legitimate data table structures is data table
	if (node.tHead || node.tFoot || node.caption) {
		return true;
	}
	// colgroup / col - colgroup is magically generated
	for (var childIndex = 0, childLength = node.children.length; childIndex < childLength; childIndex++) {
		if (node.children[childIndex].nodeName.toUpperCase() === 'COLGROUP') {
			return true;
		}
	}

	var cells = 0;
	var rowLength = node.rows.length;
	var row, cell;
	var hasBorder = false;
	for (var rowIndex = 0; rowIndex < rowLength; rowIndex++) {
		row = node.rows[rowIndex];
		for (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {
			cell = row.cells[cellIndex];
			if (!hasBorder && (cell.offsetWidth !== cell.clientWidth || cell.offsetHeight !== cell.clientHeight)) {
				hasBorder = true;
			}
			if (cell.getAttribute('scope') || cell.getAttribute('headers') || cell.getAttribute('abbr')) {
				return true;
			}
			if (cell.nodeName.toUpperCase() === 'TH') {
				return true;
			}
			// abbr element as a single child element of table cell
			if (cell.children.length === 1 && cell.children[0].nodeName.toUpperCase() === 'ABBR') {
				return true;
			}
			cells++;
		}
	}

	// Table having nested table is layout table
	if (node.getElementsByTagName('table').length) {
		return false;
	}

	// Table having only one row or column is layout table (row)
	if (rowLength < 2) {
		return false;
	}

	// Table having only one row or column is layout table (column)
	var sampleRow = node.rows[Math.ceil(rowLength / 2)];
	if (sampleRow.cells.length === 1 && sampleRow.cells[0].colSpan === 1) {
		return false;
	}

	// Table having many columns (>= 5) is data table
	if (sampleRow.cells.length >= 5) {
		return true;
	}

	// Table having borders around cells is data table
	if (hasBorder) {
		return true;
	}

	// Table having differently colored rows is data table
	var bgColor, bgImage;
	for (rowIndex = 0; rowIndex < rowLength; rowIndex++) {
		row = node.rows[rowIndex];
		if (bgColor && bgColor !== window.getComputedStyle(row).getPropertyValue('background-color')) {
			return true;
		} else {
			bgColor = window.getComputedStyle(row).getPropertyValue('background-color');
		}
		if (bgImage && bgImage !== window.getComputedStyle(row).getPropertyValue('background-image')) {
			return true;
		} else {
			bgImage = window.getComputedStyle(row).getPropertyValue('background-image');
		}

	}

	// Table having many rows (>= 20) is data table
	if (rowLength >= 20) {
		return true;
	}

	// Wide table (more than 95% of the document width) is layout table
	if (dom.getElementCoordinates(node).width > dom.getViewportSize(window).width * 0.95) {
		return false;
	}

	// Table having small amount of cells (<= 10) is layout table
	if (cells < 10) {
		return false;
	}

	// Table containing embed, object, applet of iframe elements (typical advertisements elements) is layout table
	if (node.querySelector('object, embed, iframe, applet')) {
		return false;
	}

	// Otherwise it's data table
	return true;
};

/*global table, utils */

/**
 * Determine if a `HTMLTableCellElement` is a header
 * @param  {HTMLTableCellElement}  node The table cell to test
 * @return {Boolean}
 */
table.isHeader = function (cell) {
	if (table.isColumnHeader(cell) || table.isRowHeader(cell)) {
		return true;
	}

	if (cell.id) {
		return !!document.querySelector('[headers~="' + utils.escapeSelector(cell.id) + '"]');
	}

	return false;
};

/*global table, dom */

/**
 * Determine if a `HTMLTableCellElement` is a row header
 * @param  {HTMLTableCellElement}  node The table cell to test
 * @return {Boolean}
 */
table.isRowHeader = function (node) {


	var scope = node.getAttribute('scope');
	if (scope === 'row') {
		return true;
	} else if (scope || node.nodeName.toUpperCase() !== 'TH') {
		return false;
	}

	if (table.isColumnHeader(node)) {
		return false;
	}

	var currentCell,
		position = table.getCellPosition(node),
		tbl = table.toArray(dom.findUp(node, 'table'));

	for (var rowIndex = 0, rowLength = tbl.length; rowIndex < rowLength; rowIndex++) {
		currentCell = tbl[rowIndex][position.x];
		if (currentCell !== node) {
			if (table.isDataCell(currentCell)) {
				return false;
			}
		}
	}

	return true;

};
/*global table */

/**
 * Converts a table to an Array, normalized for row and column spans
 * @param  {HTMLTableElement} node The table to convert
 * @return {Array}      Array of rows and cells
 */
table.toArray = function (node) {
	var table = [];
	var rows = node.rows;
	for (var i = 0, rowLength = rows.length; i < rowLength; i++) {
		var cells = rows[i].cells;
		table[i] = table[i] || [];

		var columnIndex = 0;

		for (var j = 0, cellLength = cells.length; j < cellLength; j++) {
			for (var colSpan = 0; colSpan < cells[j].colSpan; colSpan++) {
				for (var rowSpan = 0; rowSpan < cells[j].rowSpan; rowSpan++) {
					table[i + rowSpan] = table[i + rowSpan] || [];
					while (table[i + rowSpan][columnIndex]) {
						columnIndex++;
					}
					table[i + rowSpan][columnIndex] = cells[j];
				}
				columnIndex++;
			}
		}
	}

	return table;
};

/*global text, dom, aria, utils */
/*jshint maxstatements: 25, maxcomplexity: 19 */

var defaultButtonValues = {
	submit: 'Submit',
	reset: 'Reset'
};

var inputTypes = ['text', 'search', 'tel', 'url', 'email', 'date', 'time', 'number', 'range', 'color'];
var phrasingElements = ['a', 'em', 'strong', 'small', 'mark', 'abbr', 'dfn', 'i', 'b', 's', 'u', 'code',
	'var', 'samp', 'kbd', 'sup', 'sub', 'q', 'cite', 'span', 'bdo', 'bdi', 'br', 'wbr', 'ins', 'del', 'img',
	'embed', 'object', 'iframe', 'map', 'area', 'script', 'noscript', 'ruby', 'video', 'audio', 'input',
	'textarea', 'select', 'button', 'label', 'output', 'datalist', 'keygen', 'progress', 'command',
	'canvas', 'time', 'meter'];

/**
 * Find a non-ARIA label for an element
 *
 * @param {HTMLElement} element The HTMLElement
 * @return {HTMLElement} The label element, or null if none is found
 */
function findLabel(element) {
	var ref = null;
	if (element.id) {
		ref = document.querySelector('label[for="' + utils.escapeSelector(element.id) + '"]');
		if (ref) {
			return ref;
		}
	}
	ref = dom.findUp(element, 'label');
	return ref;
}

function isButton(element) {
	return ['button', 'reset', 'submit'].indexOf(element.type) !== -1;
}

function isInput(element) {
	var nodeName = element.nodeName.toUpperCase();
	return (nodeName === 'TEXTAREA' || nodeName === 'SELECT') ||
		(nodeName === 'INPUT' && element.type !== 'hidden');
}

function shouldCheckSubtree(element) {
	return ['BUTTON', 'SUMMARY', 'A'].indexOf(element.nodeName.toUpperCase()) !== -1;
}

function shouldNeverCheckSubtree(element) {
	return ['TABLE', 'FIGURE'].indexOf(element.nodeName.toUpperCase()) !== -1;
}

/**
 * Calculate value of a form element when treated as a value
 *
 * @param {HTMLElement} element The HTMLElement
 * @return {string} The calculated value
 */
function formValueText(element) {
	var nodeName = element.nodeName.toUpperCase();
	if (nodeName === 'INPUT') {
		if (!element.hasAttribute('type') || (inputTypes.indexOf(element.getAttribute('type')) !== -1) && element.value) {
			return element.value;
		}
		return '';
	}

	if (nodeName === 'SELECT') {
		var opts = element.options;
		if (opts && opts.length) {
			var returnText = '';
			for (var i = 0; i < opts.length; i++) {
				if (opts[i].selected) {
					returnText += ' ' + opts[i].text;
				}
			}
			return text.sanitize(returnText);
		}
		return '';
	}

	if (nodeName === 'TEXTAREA' && element.value) {
		return element.value;
	}
	return '';
}

function checkDescendant(element, nodeName) {
	var candidate = element.querySelector(nodeName);
	if (candidate) {
		return text.accessibleText(candidate);
	}

	return '';
}


/**
 * Determine whether an element can be an embedded control
 *
 * @param {HTMLElement} element The HTMLElement
 * @return {boolean} True if embedded control
 */
function isEmbeddedControl(e) {
	if (!e) {
		return false;
	}
	switch (e.nodeName.toUpperCase()) {
		case 'SELECT':
		case 'TEXTAREA':
			return true;
		case 'INPUT':
			return !e.hasAttribute('type') || (inputTypes.indexOf(e.getAttribute('type')) !== -1);
		default:
			return false;
	}
}

function shouldCheckAlt(element) {
	var nodeName = element.nodeName.toUpperCase();
	return (nodeName === 'INPUT' && element.type === 'image') ||
		['IMG', 'APPLET', 'AREA'].indexOf(nodeName) !== -1;
}

function nonEmptyText(t) {
	return !!text.sanitize(t);
}

/**
 * Determine the accessible text of an element, using logic from ARIA:
 * http://www.w3.org/TR/html-aam-1.0/
 * http://www.w3.org/TR/wai-aria/roles#textalternativecomputation
 *
 * @param {HTMLElement} element The HTMLElement
 * @return {string}
 */
text.accessibleText = function(element) {

	function checkNative(element, inLabelledByContext, inControlContext) {
		var returnText = '',
			nodeName = element.nodeName.toUpperCase();
		if (shouldCheckSubtree(element)) {
			returnText = getInnerText(element, false, false) || '';
			if (nonEmptyText(returnText)) {
				return returnText;
			}
		}
		if (nodeName === 'FIGURE') {
			returnText = checkDescendant(element, 'figcaption');

			if (nonEmptyText(returnText)) {
				return returnText;
			}
		}

		if (nodeName === 'TABLE') {
			returnText = checkDescendant(element, 'caption');

			if (nonEmptyText(returnText)) {
				return returnText;
			}

			returnText = element.getAttribute('title') || element.getAttribute('summary') || '';

			if (nonEmptyText(returnText)) {
				return returnText;
			}
		}

		if (shouldCheckAlt(element)) {
			return element.getAttribute('alt') || '';
		}

		if (isInput(element) && !inControlContext) {
			if (isButton(element)) {
				return element.value || element.title || defaultButtonValues[element.type] || '';
			}

			var labelElement = findLabel(element);
			if (labelElement) {
				return accessibleNameComputation(labelElement, inLabelledByContext, true);
			}
		}

		return '';
	}

	function checkARIA(element, inLabelledByContext, inControlContext) {

		if (!inLabelledByContext && element.hasAttribute('aria-labelledby')) {
			return text.sanitize(dom.idrefs(element, 'aria-labelledby').map(function(l) {
				if (element === l) {
					encounteredNodes.pop();
				} //let element be encountered twice
				return accessibleNameComputation(l, true, element !== l);
			}).join(' '));
		}

		if (!(inControlContext && isEmbeddedControl(element)) && element.hasAttribute('aria-label')) {
			return text.sanitize(element.getAttribute('aria-label'));
		}

		return '';
	}

	function getInnerText(element, inLabelledByContext, inControlContext) {

		var nodes = element.childNodes;
		var returnText = '';
		var node;

		for (var i = 0; i < nodes.length; i++) {
			node = nodes[i];
			if (node.nodeType === 3) {
				returnText += node.textContent;
			} else if (node.nodeType === 1) {
				if (phrasingElements.indexOf(node.nodeName.toLowerCase()) === -1) {
					returnText += ' ';
				}
				returnText += accessibleNameComputation(nodes[i], inLabelledByContext, inControlContext);
			}
		}

		return returnText;

	}


	var encounteredNodes = [];

	/**
	 * Determine the accessible text of an element, using logic from ARIA:
	 * http://www.w3.org/TR/accname-aam-1.1/#mapping_additional_nd_name
	 *
	 * @param {HTMLElement} element The HTMLElement
	 * @param {Boolean} inLabelledByContext True when in the context of resolving a labelledBy
	 * @param {Boolean} inControlContext True when in the context of textifying a widget
	 * @return {string}
	 */
	function accessibleNameComputation(element, inLabelledByContext, inControlContext) {
		'use strict';

		var returnText = '';

		//Step 2a
		if (element === null || !dom.isVisible(element, true) || (encounteredNodes.indexOf(element) !== -1)) {
			return '';
		}
		encounteredNodes.push(element);
		var role = element.getAttribute('role');

		//Step 2b & 2c
		returnText += checkARIA(element, inLabelledByContext, inControlContext);
		if (nonEmptyText(returnText)) {
			return returnText;
		}

		//Step 2d - native attribute or elements
		returnText = checkNative(element, inLabelledByContext, inControlContext);
		if (nonEmptyText(returnText)) {
			return returnText;
		}

		//Step 2e
		if (inControlContext) {
			returnText += formValueText(element);
			if (nonEmptyText(returnText)) {
				return returnText;
			}
		}

		//Step 2f
		if (!shouldNeverCheckSubtree(element) && (!role || aria.getRolesWithNameFromContents().indexOf(role) !== -1)) {

			returnText = getInnerText(element, inLabelledByContext, inControlContext);

			if (nonEmptyText(returnText)) {
				return returnText;
			}
		}

		//Step 2g - if text node, return value (handled in getInnerText)

		//Step 2h
		if (element.hasAttribute('title')) {
			return element.getAttribute('title');
		}

		return '';
	}

	return text.sanitize(accessibleNameComputation(element));
};

/*global text, dom, utils, aria */
/**
 * Gets the visible text of a label for a given input
 * @see http://www.w3.org/WAI/PF/aria/roles#namecalculation
 * @param  {HTMLElement} node The input to test
 * @return {Mixed}      String of visible text, or `null` if no label is found
 */
text.label = function (node) {
	var ref, candidate;

	candidate = aria.label(node);
	if (candidate) {
		return candidate;
	}

	// explicit label
	if (node.id) {
		ref = document.querySelector('label[for="' + utils.escapeSelector(node.id) + '"]');
		candidate = ref && text.visible(ref, true);
		if (candidate) {
			return candidate;
		}
	}

	ref = dom.findUp(node, 'label');
	candidate = ref && text.visible(ref, true);
	if (candidate) {
		return candidate;
	}

	return null;
};

/*global text */
text.sanitize = function (str) {
	'use strict';
	return str
		.replace(/\r\n/g, '\n')
		.replace(/\u00A0/g, ' ')
		.replace(/[\s]{2,}/g, ' ')
		.trim();
};

/*global text, dom */

text.visible = function (element, screenReader, noRecursing) {
	'use strict';

	var index, child, nodeValue,
		childNodes = element.childNodes,
		length = childNodes.length,
		result = '';

	for (index = 0; index < length; index++) {
		child = childNodes[index];

		if (child.nodeType === 3) {
			nodeValue = child.nodeValue;
			if (nodeValue && dom.isVisible(element, screenReader)) {
				result += child.nodeValue;
			}
		} else if (!noRecursing) {
			result += text.visible(child, screenReader);
		}
	}

	return text.sanitize(result);
};

/*global utils */
utils.toArray = function (thing) {
	'use strict';
	return Array.prototype.slice.call(thing);
};
/*global utils */


utils.tokenList = function (str) {
	'use strict';

	return str.trim().replace(/\s{2,}/g, ' ').split(' ');
};
	return commons;
}())
});

	axe.version = '1.1.1';
	if (typeof define === "function" && define.amd) this.axe = axe, define(axe); else if (typeof module === "object" && module.exports) module.exports = axe; else window.axe = axe;
}(window, window.document));
module.exports.source = "/*! aXe v1.1.1\n * Copyright (c) 2016 Deque Systems, Inc.\n *\n * Your use of this Source Code Form is subject to the terms of the Mozilla Public\n * License, v. 2.0. If a copy of the MPL was not distributed with this\n * file, You can obtain one at http://mozilla.org/MPL/2.0/.\n *\n * This entire copyright notice must appear in every copy of this file you\n * distribute or in any file that contains substantial portions of this source\n * code.\n */\n(function (window, document) {\n\n/*exported axe, require, define, commons */\n// exported namespace for aXe\nvar axe = {};\n\n// local namespace for common functions\nvar commons;\n\n/*global matchesSelector, escapeSelector, clone */\n/*exported utils */\nvar utils = axe.utils = {};\n\nutils.matchesSelector = matchesSelector;\nutils.escapeSelector = escapeSelector;\nutils.clone = clone;\n\n/*exported helpers */\nvar helpers = {};\n\n/*global Rule, Tool, Check, injectStyle, commons: true */\n\nfunction setDefaultConfiguration(audit) {\n\t'use strict';\n\n\tvar config = audit || {};\n\tconfig.rules = config.rules || [];\n\tconfig.tools = config.tools || [];\n\tconfig.checks = config.checks || [];\n\tconfig.data = config.data || {\n\t\tchecks: {},\n\t\trules: {}\n\t};\n\n\treturn config;\n}\n\nfunction unpackToObject(collection, audit, method) {\n\t'use strict';\n\n\tvar i, l;\n\tfor (i = 0, l = collection.length; i < l; i++) {\n\t\taudit[method](collection[i]);\n\t}\n}\n\n/**\n * Constructor which holds configured rules and information about the document under test\n */\nfunction Audit(audit) {\n\t'use strict';\n\taudit = setDefaultConfiguration(audit);\n\n\taxe.commons = commons = audit.commons;\n\n\tthis.reporter = audit.reporter;\n\tthis.rules = [];\n\tthis.tools = {};\n\tthis.checks = {};\n\n\tunpackToObject(audit.rules, this, 'addRule');\n\tunpackToObject(audit.tools, this, 'addTool');\n\tunpackToObject(audit.checks, this, 'addCheck');\n\tthis.data = audit.data || {\n\t\tchecks: {},\n\t\trules: {}\n\t};\n\n\tinjectStyle(audit.style);\n}\n\n/**\n * Adds a new rule to the Audit.  If a rule with specified ID already exists, it will be overridden\n * @param {Object} spec Rule specification object\n */\nAudit.prototype.addRule = function (spec) {\n\t'use strict';\n\n\tif (spec.metadata) {\n\t\tthis.data.rules[spec.id] = spec.metadata;\n\t}\n\n\tvar candidate;\n\tfor (var i = 0, l = this.rules.length; i < l; i++) {\n\t\tcandidate = this.rules[i];\n\t\tif (candidate.id === spec.id) {\n\t\t\tthis.rules[i] = new Rule(spec, this);\n\t\t\treturn;\n\t\t}\n\t}\n\n\tthis.rules.push(new Rule(spec, this));\n};\n\n/**\n * Adds a new tool to the Audit.  If a tool with specified ID already exists, it will be overridden\n * @param {Object} spec Tool specification object\n */\nAudit.prototype.addTool = function (spec) {\n\t'use strict';\n\tthis.tools[spec.id] = new Tool(spec);\n};\n\n/**\n * Adds a new check to the Audit.  If a Check with specified ID already exists, it will be overridden\n * @param {Object} spec Check specification object\n */\nAudit.prototype.addCheck = function (spec) {\n\t'use strict';\n\n\tif (spec.metadata) {\n\t\tthis.data.checks[spec.id] = spec.metadata;\n\t}\n\n\tthis.checks[spec.id] = new Check(spec);\n};\n\n/**\n * Runs the Audit; which in turn should call `run` on each rule.\n * @async\n * @param  {Context}   context The scope definition/context for analysis (include/exclude)\n * @param  {Object}    options Options object to pass into rules and/or disable rules or checks\n * @param  {Function} fn       Callback function to fire when audit is complete\n */\nAudit.prototype.run = function (context, options, fn) {\n\t'use strict';\n\n\tvar q = utils.queue();\n\tthis.rules.forEach(function (rule) {\n\t\tif (utils.ruleShouldRun(rule, context, options)) {\n\t\t\tq.defer(function (cb) {\n\t\t\t\trule.run(context, options, cb);\n\t\t\t});\n\t\t}\n\t});\n\tq.then(fn);\n};\n\n/**\n * Runs Rule `after` post processing functions\n * @param  {Array} results  Array of RuleResults to postprocess\n * @param  {Mixed} options  Options object to pass into rules and/or disable rules or checks\n */\nAudit.prototype.after = function (results, options) {\n\t'use strict';\n\n\tvar rules = this.rules;\n\n\treturn results.map(function (ruleResult) {\n\t\tvar rule = utils.findBy(rules, 'id', ruleResult.id);\n\n\t\treturn rule.after(ruleResult, options);\n\t});\n};\n\n/*exported CheckResult */\n\n/**\n * Constructor for the result of checks\n * @param {Check} check\n */\nfunction CheckResult(check) {\n\t'use strict';\n\n\t/**\n\t * ID of the check.  Unique in the context of a rule.\n\t * @type {String}\n\t */\n\tthis.id = check.id;\n\n\t/**\n\t * Any data passed by Check (by calling `this.data()`)\n\t * @type {Mixed}\n\t */\n\tthis.data = null;\n\n\t/**\n\t * Any node that is related to the Check, specified by calling `this.relatedNodes([HTMLElement...])` inside the Check\n\t * @type {Array}\n\t */\n\tthis.relatedNodes = [];\n\n\t/**\n\t * The return value of the Check's evaluate function\n\t * @type {Mixed}\n\t */\n\tthis.result = null;\n}\n\n/*global CheckResult */\n\nfunction Check(spec) {\n\t'use strict';\n\n\t/**\n\t * Unique ID for the check.  Checks may be re-used, so there may be additional instances of checks\n\t * with the same ID.\n\t * @type {String}\n\t */\n\tthis.id = spec.id;\n\n\t/**\n\t * Free-form options that are passed as the second parameter to the `evaluate`\n\t * @type {Mixed}\n\t */\n\tthis.options = spec.options;\n\n\t/**\n\t * Optional. If specified, only nodes that match this CSS selector are tested\n\t * @type {String}\n\t */\n\tthis.selector = spec.selector;\n\n\t/**\n\t * The actual code, accepts 2 parameters: node (the node under test), options (see this.options).\n\t * This function is run in the context of a checkHelper, which has the following methods\n\t * - `async()` - if called, the check is considered to be asynchronous; returns a callback function\n\t * - `data()` - free-form data object, associated to the `CheckResult` which is specific to each node\n\t * @type {Function}\n\t */\n\tthis.evaluate = spec.evaluate;\n\n\t/**\n\t * Optional. Filter and/or modify checks for all nodes\n\t * @type {Function}\n\t */\n\tif (spec.after) {\n\t\tthis.after = spec.after;\n\t}\n\n\tif (spec.matches) {\n\t\t/**\n\t\t * Optional function to test if check should be run against a node, overrides Check#matches\n\t\t * @type {Function}\n\t\t */\n\t\tthis.matches = spec.matches;\n\t}\n\n\t/**\n\t * enabled by default, if false, this check will not be included in the rule's evaluation\n\t * @type {Boolean}\n\t */\n\tthis.enabled = spec.hasOwnProperty('enabled') ? spec.enabled : true;\n}\n\n/**\n * Determines whether the check should be run against a node\n * @param  {HTMLElement} node The node to test\n * @return {Boolean}      Whether the check should be run\n */\nCheck.prototype.matches = function (node) {\n\t'use strict';\n\n\tif (!this.selector || utils.matchesSelector(node, this.selector)) {\n\t\treturn true;\n\t}\n\n\treturn false;\n};\n\n/**\n * Run the check's evaluate function (call `this.evaluate(node, options)`)\n * @param  {HTMLElement} node  The node to test\n * @param  {Object} options    The options that override the defaults and provide additional\n *                             information for the check\n * @param  {Function} callback Function to fire when check is complete\n */\nCheck.prototype.run = function (node, options, callback) {\n\t'use strict';\n\toptions = options || {};\n\tvar enabled = options.hasOwnProperty('enabled') ? options.enabled : this.enabled,\n\t\tcheckOptions = options.options || this.options;\n\n\tif (enabled && this.matches(node)) {\n\t\tvar checkResult = new CheckResult(this);\n\t\tvar checkHelper = utils.checkHelper(checkResult, callback);\n\t\tvar result;\n\n\t\ttry {\n\t\t\tresult = this.evaluate.call(checkHelper, node, checkOptions);\n\t\t} catch (e) {\n\t\t\taxe.log(e.message, e.stack);\n\t\t\tcallback(null);\n\t\t\treturn;\n\t\t}\n\n\t\tif (!checkHelper.isAsync) {\n\t\t\tcheckResult.result = result;\n\t\t\tsetTimeout(function () {\n\t\t\t\tcallback(checkResult);\n\t\t\t}, 0);\n\t\t}\n\t} else {\n\t\tcallback(null);\n\t}\n};\n\n/*exported Context */\n/*global isNodeInContext */\n/**\n * Pushes a unique frame onto `frames` array, filtering any hidden iframes\n * @private\n * @param  {Context} context The context object to operate on and assign to\n * @param  {HTMLElement} frame   The frame to push onto Context\n */\nfunction pushUniqueFrame(collection, frame) {\n\t'use strict';\n\tif (utils.isHidden(frame)) {\n\t\treturn;\n\t}\n\n\tvar fr = utils.findBy(collection, 'node', frame);\n\n\tif (!fr) {\n\t\tcollection.push({\n\t\t\tnode: frame,\n\t\t\tinclude: [],\n\t\t\texclude: []\n\t\t});\n\t}\n\n}\n\n/**\n * Unshift selectors of matching iframes\n * @private\n * @param  {Context} context The context object to operate on and assign to\n * @param  {String} type          The \"type\" of context, 'include' or 'exclude'\n * @param  {Array} selectorArray  Array of CSS selectors, each element represents a frame;\n * where the last element is the actual node\n */\nfunction pushUniqueFrameSelector(context, type, selectorArray) {\n\t'use strict';\n\n\tcontext.frames = context.frames || [];\n\n\tvar result, frame;\n\tvar frames = document.querySelectorAll(selectorArray.shift());\n\n\tframeloop:\n\tfor (var i = 0, l = frames.length; i < l; i++) {\n\t\tframe = frames[i];\n\t\tfor (var j = 0, l2 = context.frames.length; j < l2; j++) {\n\t\t\tif (context.frames[j].node === frame) {\n\t\t\t\tcontext.frames[j][type].push(selectorArray);\n\t\t\t\tbreak frameloop;\n\t\t\t}\n\t\t}\n\t\tresult = {\n\t\t\tnode: frame,\n\t\t\tinclude: [],\n\t\t\texclude: []\n\t\t};\n\n\t\tif (selectorArray) {\n\t\t\tresult[type].push(selectorArray);\n\t\t}\n\n\t\tcontext.frames.push(result);\n\t}\n}\n\n/**\n * Normalize the input of \"context\" so that many different methods of input are accepted\n * @private\n * @param  {Mixed} context  The configuration object passed to `Context`\n * @return {Object}         Normalized context spec to include both `include` and `exclude` arrays\n */\nfunction normalizeContext(context) {\n\t'use strict';\n\n\t// typeof NodeList.length in PhantomJS === function\n\tif (context && typeof context === 'object' || context instanceof NodeList) {\n\n\t\tif (context instanceof Node) {\n\t\t\treturn {\n\t\t\t\tinclude: [context],\n\t\t\t\texclude: []\n\t\t\t};\n\t\t}\n\n\t\tif (context.hasOwnProperty('include') || context.hasOwnProperty('exclude')) {\n\t\t\treturn {\n\t\t\t\tinclude: context.include || [document],\n\t\t\t\texclude: context.exclude || []\n\t\t\t};\n\t\t}\n\n\t\tif (context.length === +context.length) {\n\t\t\treturn {\n\t\t\t\tinclude: context,\n\t\t\t\texclude: []\n\t\t\t};\n\t\t}\n\t}\n\n\tif (typeof context === 'string') {\n\t\treturn {\n\t\t\tinclude: [context],\n\t\t\texclude: []\n\t\t};\n\t}\n\n\treturn {\n\t\tinclude: [document],\n\t\texclude: []\n\t};\n}\n\n/**\n * Finds frames in context, converts selectors to Element references and pushes unique frames\n * @private\n * @param  {Context} context The instance of Context to operate on\n * @param  {String} type     The \"type\" of thing to parse, \"include\" or \"exclude\"\n * @return {Array}           Parsed array of matching elements\n */\nfunction parseSelectorArray(context, type) {\n\t'use strict';\n\n\tvar item,\n\t\tresult = [];\n\tfor (var i = 0, l = context[type].length; i < l; i++) {\n\t\titem = context[type][i];\n\t\t// selector\n\t\tif (typeof item === 'string') {\n\t\t\tresult = result.concat(utils.toArray(document.querySelectorAll(item)));\n\t\t\tbreak;\n\t\t} else if (item && item.length) {\n\n\t\t\tif (item.length > 1) {\n\t\t\t\tpushUniqueFrameSelector(context, type, item);\n\t\t\t} else {\n\t\t\t\tresult = result.concat(utils.toArray(document.querySelectorAll(item[0])));\n\t\t\t}\n\t\t} else {\n\t\t\tresult.push(item);\n\t\t}\n\t}\n\n\t// filter nulls\n\treturn result.filter(function (r) {\n\t\treturn r;\n\t});\n}\n\n/**\n * Holds context of includes, excludes and frames for analysis.\n *\n * @todo  clarify and sync changes to design doc\n * Context : {IncludeStrings} || {\n *   // defaults to document/all\n *   include: {IncludeStrings},\n *   exclude : {ExcludeStrings}\n * }\n *\n * IncludeStrings : [{CSSSelectorArray}] || Node\n * ExcludeStrings : [{CSSSelectorArray}]\n * `CSSSelectorArray` an Array of selector strings that addresses a Node in a multi-frame document. All addresses\n * are in this form regardless of whether the document contains any frames.To evaluate the selectors to\n * find the node referenced by the array, evaluate the selectors in-order, starting in window.top. If N\n * is the length of the array, then the first N-1 selectors should result in an iframe and the last\n * selector should result in the specific node.\n *\n * @param {Object} spec Configuration or \"specification\" object\n */\nfunction Context(spec) {\n\t'use strict';\n\tvar self = this;\n\n\tthis.frames = [];\n\tthis.initiator = (spec && typeof spec.initiator === 'boolean') ? spec.initiator : true;\n\tthis.page = false;\n\n\tspec = normalizeContext(spec);\n\tthis.exclude = spec.exclude;\n\tthis.include = spec.include;\n\n\tthis.include = parseSelectorArray(this, 'include');\n\tthis.exclude = parseSelectorArray(this, 'exclude');\n\n\tutils.select('frame, iframe', this).forEach(function (frame) {\n\t\tif (isNodeInContext(frame, self)) {\n\t\t\tpushUniqueFrame(self.frames, frame);\n\t\t}\n\t});\n\n\tif (this.include.length === 1 && this.include[0] === document) {\n\t\tthis.page = true;\n\t}\n\n}\n\n/*exported RuleResult */\n\n/**\n * Constructor for the result of Rules\n * @param {Rule} rule\n */\nfunction RuleResult(rule) {\n\t'use strict';\n\n\t/**\n\t * The ID of the Rule whom this result belongs to\n\t * @type {String}\n\t */\n\tthis.id = rule.id;\n\n\t/**\n\t * The calculated result of the Rule, either PASS, FAIL or NA\n\t * @type {String}\n\t */\n\tthis.result = axe.constants.result.NA;\n\n\t/**\n\t * Whether the Rule is a \"pageLevel\" rule\n\t * @type {Boolean}\n\t */\n\tthis.pageLevel = rule.pageLevel;\n\n\t/**\n\t * Impact of the violation\n\t * @type {String}  Plain-english impact or null if rule passes\n\t */\n\tthis.impact = null;\n\n\t/**\n\t * Holds information regarding nodes and individual CheckResults\n\t * @type {Array}\n\t */\n\tthis.nodes = [];\n}\n\n/*global RuleResult */\n\nfunction Rule(spec, parentAudit) {\n\t'use strict';\n\n\tthis._audit = parentAudit;\n\n\t/**\n\t * The code, or string ID of the rule\n\t * @type {String}\n\t */\n\tthis.id = spec.id;\n\n\t/**\n\t * Selector that this rule applies to\n\t * @type {String}\n\t */\n\tthis.selector = spec.selector || '*';\n\n\t/**\n\t * Whether to exclude hiddden elements form analysis.  Defaults to true.\n\t * @type {Boolean}\n\t */\n\tthis.excludeHidden = typeof spec.excludeHidden === 'boolean' ? spec.excludeHidden : true;\n\n\t/**\n\t * Flag to enable or disable rule\n\t * @type {Boolean}\n\t */\n\tthis.enabled = typeof spec.enabled === 'boolean' ? spec.enabled : true;\n\n\t/**\n\t * Denotes if the rule should be run if Context is not an entire page AND whether\n\t * the Rule should be satisified regardless of Node\n\t * @type {Boolean}\n\t */\n\tthis.pageLevel = typeof spec.pageLevel === 'boolean' ? spec.pageLevel : false;\n\n\t/**\n\t * Checks that any may return true to satisfy rule\n\t * @type {Array}\n\t */\n\tthis.any = spec.any || [];\n\n\t/**\n\t * Checks that must all return true to satisfy rule\n\t * @type {Array}\n\t */\n\tthis.all = spec.all || [];\n\n\t/**\n\t * Checks that none may return true to satisfy rule\n\t * @type {Array}\n\t */\n\tthis.none = spec.none || [];\n\n\t/**\n\t * Tags associated to this rule\n\t * @type {Array}\n\t */\n\tthis.tags = spec.tags || [];\n\n\tif (spec.matches) {\n\t\t/**\n\t\t * Optional function to test if rule should be run against a node, overrides Rule#matches\n\t\t * @type {Function}\n\t\t */\n\t\tthis.matches = spec.matches;\n\t}\n\n}\n\n/**\n * Optionally test each node against a `matches` function to determine if the rule should run against\n * a given node.  Defaults to `true`.\n * @return {Boolean}    Whether the rule should run\n */\nRule.prototype.matches = function () {\n\t'use strict';\n\n\treturn true;\n};\n\n/**\n * Selects `HTMLElement`s based on configured selector\n * @param  {Context} context The resolved Context object\n * @return {Array}           All matching `HTMLElement`s\n */\nRule.prototype.gather = function (context) {\n\t'use strict';\n\tvar elements = utils.select(this.selector, context);\n\tif (this.excludeHidden) {\n\t\treturn elements.filter(function (element) {\n\t\t\treturn !utils.isHidden(element);\n\t\t});\n\t}\n\treturn elements;\n};\n\nRule.prototype.runChecks = function (type, node, options, callback) {\n\t'use strict';\n\n\tvar self = this;\n\tvar checkQueue = utils.queue();\n\tthis[type].forEach(function (c) {\n\t\tvar check = self._audit.checks[c.id || c];\n\t\tvar option = utils.getCheckOption(check, self.id, options);\n\t\tcheckQueue.defer(function (done) {\n\t\t\tcheck.run(node, option, done);\n\t\t});\n\t});\n\n\tcheckQueue.then(function (results) {\n\t\tresults = results.filter(function (check) {\n\t\t\treturn check;\n\t\t});\n\t\tcallback({ type: type, results: results });\n\t});\n\n};\n\n/**\n * Runs the Rule's `evaluate` function\n * @param  {Context}   context  The resolved Context object\n * @param  {Mixed}   options  Options specific to this rule\n * @param  {Function} callback Function to call when evaluate is complete; receives a RuleResult instance\n */\nRule.prototype.run = function (context, options, callback) {\n\t'use strict';\n\n\tvar nodes = this.gather(context);\n\tvar q = utils.queue();\n\tvar self = this;\n\tvar ruleResult;\n\n\truleResult = new RuleResult(this);\n\tnodes.forEach(function (node) {\n\t\tif (self.matches(node)) {\n\t\t\tq.defer(function (nodeQueue) {\n\t\t\t\tvar checkQueue = utils.queue();\n\t\t\t\tcheckQueue.defer(function (done) {\n\t\t\t\t\tself.runChecks('any', node, options, done);\n\t\t\t\t});\n\t\t\t\tcheckQueue.defer(function (done) {\n\t\t\t\t\tself.runChecks('all', node, options, done);\n\t\t\t\t});\n\t\t\t\tcheckQueue.defer(function (done) {\n\t\t\t\t\tself.runChecks('none', node, options, done);\n\t\t\t\t});\n\n\t\t\t\tcheckQueue.then(function (results) {\n\t\t\t\t\tif (results.length) {\n\t\t\t\t\t\tvar hasResults = false,\n\t\t\t\t\t\t\tresult = {\n\t\t\t\t\t\t\t\tnode: new utils.DqElement(node)\n\t\t\t\t\t\t\t};\n\t\t\t\t\t\tresults.forEach(function (r) {\n\t\t\t\t\t\t\tvar res = r.results.filter(function (result) {\n\t\t\t\t\t\t\t\treturn result;\n\t\t\t\t\t\t\t});\n\t\t\t\t\t\t\tresult[r.type] = res;\n\t\t\t\t\t\t\tif (res.length) {\n\t\t\t\t\t\t\t\thasResults = true;\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t});\n\t\t\t\t\t\tif (hasResults) {\n\t\t\t\t\t\t\truleResult.nodes.push(result);\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t\tnodeQueue();\n\t\t\t\t});\n\n\t\t\t});\n\t\t}\n\t});\n\n\tq.then(function () {\n\t\tcallback(ruleResult);\n\t});\n\n};\n\n/**\n * Iterates the rule's Checks looking for ones that have an after function\n * @private\n * @param  {Rule} rule The rule to check for after checks\n * @return {Array}      Checks that have an after function\n */\nfunction findAfterChecks(rule) {\n\t'use strict';\n\n\treturn utils.getAllChecks(rule).map(function (c) {\n\t\tvar check = rule._audit.checks[c.id || c];\n\t\treturn typeof check.after === 'function' ? check : null;\n\t}).filter(Boolean);\n}\n\n/**\n * Finds and collates all results for a given Check on a specific Rule\n * @private\n * @param  {Array} nodes RuleResult#nodes; array of 'detail' objects\n * @param  {String} checkID The ID of the Check to find\n * @return {Array}         Matching CheckResults\n */\nfunction findCheckResults(nodes, checkID) {\n\t'use strict';\n\n\tvar checkResults = [];\n\tnodes.forEach(function (nodeResult) {\n\t\tvar checks = utils.getAllChecks(nodeResult);\n\t\tchecks.forEach(function (checkResult) {\n\t\t\tif (checkResult.id === checkID) {\n\t\t\t\tcheckResults.push(checkResult);\n\t\t\t}\n\t\t});\n\t});\n\treturn checkResults;\n}\n\nfunction filterChecks(checks) {\n\t'use strict';\n\n\treturn checks.filter(function (check) {\n\t\treturn check.filtered !== true;\n\t});\n}\n\nfunction sanitizeNodes(result) {\n\t'use strict';\n\tvar checkTypes = ['any', 'all', 'none'];\n\n\tvar nodes = result.nodes.filter(function (detail) {\n\t\tvar length = 0;\n\t\tcheckTypes.forEach(function (type) {\n\t\t\tdetail[type] = filterChecks(detail[type]);\n\t\t\tlength += detail[type].length;\n\t\t});\n\t\treturn length > 0;\n\t});\n\n\tif (result.pageLevel && nodes.length) {\n\t\tnodes = [nodes.reduce(function (a, b) {\n\t\t\tif (a) {\n\t\t\t\tcheckTypes.forEach(function (type) {\n\t\t\t\t\ta[type].push.apply(a[type], b[type]);\n\t\t\t\t});\n\t\t\t\treturn a;\n\t\t\t}\n\t\t})];\n\t}\n\treturn nodes;\n}\n\n/**\n * Runs all of the Rule's Check#after methods\n * @param  {RuleResult} result  The \"pre-after\" RuleResult\n * @param  {Mixed} options Options specific to the rule\n * @return {RuleResult}         The RuleResult as filtered by after functions\n */\nRule.prototype.after = function (result, options) {\n\t'use strict';\n\n\tvar afterChecks = findAfterChecks(this);\n\tvar ruleID = this.id;\n\tafterChecks.forEach(function (check) {\n\t\tvar beforeResults = findCheckResults(result.nodes, check.id);\n\t\tvar option = utils.getCheckOption(check, ruleID, options);\n\n\t\tvar afterResults = check.after(beforeResults, option);\n\t\tbeforeResults.forEach(function (item) {\n\t\t\tif (afterResults.indexOf(item) === -1) {\n\t\t\t\titem.filtered = true;\n\t\t\t}\n\t\t});\n\t});\n\n\tresult.nodes = sanitizeNodes(result);\n\treturn result;\n};\n\n/*exported Tool */\n\nfunction Tool(spec) {\n  'use strict';\n  spec.source = spec.source || {};\n\n  this.id = spec.id;\n  this.options = spec.options;\n  this._run = spec.source.run;\n  this._cleanup = spec.source.cleanup;\n\n  this.active = false;\n}\n\nTool.prototype.run = function (element, options, callback) {\n  'use strict';\n  options = typeof options === 'undefined' ? this.options : options;\n\n  this.active = true;\n  this._run(element, options, callback);\n};\n\nTool.prototype.cleanup = function (callback) {\n  'use strict';\n\n  this.active = false;\n  this._cleanup(callback);\n};\n\n\naxe.constants = {};\n\naxe.constants.result = {\n\tPASS: 'PASS',\n\tFAIL: 'FAIL',\n\tNA: 'NA'\n};\n\naxe.constants.raisedMetadata = {\n\timpact: ['minor', 'moderate', 'serious', 'critical']\n};\n\n/*global axe */\naxe.version = 'dev';\n\n/*jshint devel: true */\n\n/**\n * Logs a message to the developer console (if it exists and is active).\n */\naxe.log = function () {\n\t'use strict';\n\tif (typeof console === 'object' && console.log) {\n\t\t// IE does not support console.log.apply\n\t\tFunction.prototype.apply.call(console.log, console, arguments);\n\t}\n};\n\nfunction cleanupTools(callback) {\n  'use strict';\n\n  if (!axe._audit) {\n    throw new Error('No audit configured');\n  }\n\n  var q = utils.queue();\n\n  Object.keys(axe._audit.tools).forEach(function (key) {\n    var tool = axe._audit.tools[key];\n    if (tool.active) {\n      q.defer(function (done) {\n        tool.cleanup(done);\n      });\n    }\n  });\n\n  utils.toArray(document.querySelectorAll('frame, iframe')).forEach(function (frame) {\n    q.defer(function (done) {\n      return utils.sendCommandToFrame(frame, {\n        command: 'cleanup-tool'\n      }, done);\n    });\n  });\n\n  q.then(callback);\n}\naxe.cleanup = cleanupTools;\n\n/*global reporters */\naxe.configure = function (spec) {\n\t'use strict';\n\n\tvar audit = axe._audit;\n\tif (!audit) {\n\t\tthrow new Error('No audit configured');\n\t}\n\n\tif (spec.reporter && (typeof spec.reporter === 'function' || reporters[spec.reporter])) {\n\t\taudit.reporter = spec.reporter;\n\t}\n\n\tif (spec.checks) {\n\t\tspec.checks.forEach(function (check) {\n\t\t\taudit.addCheck(check);\n\t\t});\n\t}\n\n\tif (spec.rules) {\n\t\tspec.rules.forEach(function (rule) {\n\t\t\taudit.addRule(rule);\n\t\t});\n\t}\n\n\tif (spec.tools) {\n\t\tspec.tools.forEach(function (tool) {\n\t\t\taudit.addTool(tool);\n\t\t});\n\t}\n\n};\n\n/**\n * Searches and returns rules that contain a tag in the list of tags.\n * @param  {Array}   tags  Optional array of tags\n * @return {Array}  Array of rules\n */\naxe.getRules = function(tags) {\n\t'use strict';\n\n\ttags = tags || [];\n\tvar matchingRules = !tags.length ? axe._audit.rules : axe._audit.rules.filter(function(item) {\n\t\treturn !!tags.filter(function(tag) {\n\t\t\treturn item.tags.indexOf(tag) !== -1;\n\t\t}).length;\n\t});\n\n\tvar ruleData = axe._audit.data.rules || {};\n\treturn matchingRules.map(function(matchingRule) {\n\t\tvar rd = ruleData[matchingRule.id] || {};\n\t\treturn {\n\t\t\truleId: matchingRule.id,\n\t\t\tdescription: rd.description,\n\t\t\thelp: rd.help,\n\t\t\thelpUrl: rd.helpUrl,\n\t\t\ttags: matchingRule.tags,\n\t\t};\n\t});\n};\n\n/*global Audit, runRules, runTool, cleanupTools */\nfunction runCommand(data, callback) {\n\t'use strict';\n\n\tvar context = (data && data.context) || {};\n\tif (context.include && !context.include.length) {\n\t\tcontext.include = [document];\n\t}\n\tvar options = (data && data.options) || {};\n\n\tswitch(data.command) {\n\t\tcase 'rules':\n\t\t\treturn runRules(context, options, callback);\n\t\tcase 'run-tool':\n\t\t\treturn runTool(data.parameter, data.selectorArray, options, callback);\n\t\tcase 'cleanup-tool':\n\t\t\treturn cleanupTools(callback);\n\t}\n}\n\n/**\n * Sets up Rules, Messages and default options for Checks, must be invoked before attempting analysis\n * @param  {Object} audit The \"audit specifcation\" object\n * @private\n */\naxe._load = function (audit) {\n\t'use strict';\n\n\tutils.respondable.subscribe('axe.ping', function (data, respond) {\n\t\trespond({axe: true});\n\t});\n\n\tutils.respondable.subscribe('axe.start', runCommand);\n\n\taxe._audit = new Audit(audit);\n};\n\n/*exported getReporter */\nvar reporters = {};\nvar defaultReporter;\n\nfunction getReporter(reporter) {\n\t'use strict';\n\n\tif (typeof reporter === 'string' && reporters[reporter]) {\n\t\treturn reporters[reporter];\n\t}\n\n\tif (typeof reporter === 'function') {\n\t\treturn reporter;\n\t}\n\n\treturn defaultReporter;\n}\n\naxe.reporter = function registerReporter(name, cb, isDefault) {\n\t'use strict';\n\n\treporters[name] = cb;\n\tif (isDefault) {\n\t\tdefaultReporter = cb;\n\t}\n};\n\n/*global Context, getReporter */\n/*exported runRules */\n\n/**\n * Starts analysis on the current document and its subframes\n * @private\n * @param  {Object}   context  The `Context` specification object @see Context\n * @param  {Array}    options  Optional RuleOptions\n * @param  {Function} callback The function to invoke when analysis is complete; receives an array of `RuleResult`s\n */\nfunction runRules(context, options, callback) {\n\t'use strict';\n\tcontext = new Context(context);\n\n\tvar q = utils.queue();\n\tvar audit = axe._audit;\n\n\tif (context.frames.length) {\n\t\tq.defer(function (done) {\n\t\t\tutils.collectResultsFromFrames(context, options, 'rules', null, done);\n\t\t});\n\t}\n\tq.defer(function (cb) {\n\t\taudit.run(context, options, cb);\n\t});\n\tq.then(function (data) {\n\t\t// Add wrapper object so that we may use the same \"merge\" function for results from inside and outside frames\n\t\tvar results = utils.mergeResults(data.map(function (d) {\n\t\t\treturn {\n\t\t\t\tresults: d\n\t\t\t};\n\t\t}));\n\n\t\t// after should only run once, so ensure we are in the top level window\n\t\tif (context.initiator) {\n\t\t\tresults = audit.after(results, options);\n\t\t\tresults = results.map(utils.finalizeRuleResult);\n\t\t}\n\n\t\tcallback(results);\n\t});\n}\n\naxe.a11yCheck = function (context, options, callback) {\n\t'use strict';\n\tif (typeof options === 'function') {\n\t\tcallback = options;\n\t\toptions = {};\n\t}\n\n\tif (!options || typeof options !== 'object') {\n\t\toptions = {};\n\t}\n\n\tvar audit = axe._audit;\n\tif (!audit) {\n\t\tthrow new Error('No audit configured');\n\t}\n\tvar reporter = getReporter(options.reporter || audit.reporter);\n\trunRules(context, options, function (results) {\n\t\treporter(results, callback);\n\t});\n};\n\n/*exported runTool, cleanupTools */\n\nfunction runTool(toolId, selectorArray, options, callback) {\n  'use strict';\n\n  if (!axe._audit) {\n    throw new Error('No audit configured');\n  }\n\n  if (selectorArray.length > 1) {\n    var frame = document.querySelector(selectorArray.shift());\n    return utils.sendCommandToFrame(frame, {\n      options: options,\n      command: 'run-tool',\n      parameter: toolId,\n      selectorArray: selectorArray\n    }, callback);\n  }\n\n  var node = document.querySelector(selectorArray.shift());\n  axe._audit.tools[toolId].run(node, options, callback);\n}\naxe.tool = runTool;\n\n/*global helpers */\n\n/**\n * Finds failing Checks and combines each help message into an array\n * @param  {Object} nodeData Individual \"detail\" object to generate help messages for\n * @return {String}          failure messages\n */\nhelpers.failureSummary = function failureSummary(nodeData) {\n\t'use strict';\n\n\tvar failingChecks = {};\n\t// combine \"all\" and \"none\" as messaging is the same\n\tfailingChecks.none = nodeData.none.concat(nodeData.all);\n\tfailingChecks.any = nodeData.any;\n\n\treturn Object.keys(failingChecks).map(function (key) {\n\t\tif (!failingChecks[key].length) {\n\t\t\treturn;\n\t\t}\n\t\t// @todo rm .failureMessage\n\t\treturn axe._audit.data.failureSummaries[key].failureMessage(failingChecks[key].map(function (check) {\n\t\t\treturn check.message || '';\n\t\t}));\n\t}).filter(function (i) {\n\t\treturn i !== undefined;\n\t}).join('\\n\\n');\n};\n\n/*global helpers */\n\nhelpers.formatCheck = function (check) {\n\t'use strict';\n\t\n\treturn {\n\t\tid: check.id,\n\t\timpact: check.impact,\n\t\tmessage: check.message,\n\t\tdata: check.data,\n\t\trelatedNodes: check.relatedNodes.map(helpers.formatNode)\n\t};\n};\n\n/*global helpers */\nhelpers.formatChecks = function (nodeResult, data) {\n\t'use strict';\n\n\tnodeResult.any = data.any.map(helpers.formatCheck);\n\tnodeResult.all = data.all.map(helpers.formatCheck);\n\tnodeResult.none = data.none.map(helpers.formatCheck);\n\treturn nodeResult;\n};\n\n/*global helpers */\nhelpers.formatNode = function (node) {\n\t'use strict';\n\n\treturn {\n\t\ttarget: node ? node.selector : null,\n\t\thtml: node ? node.source : null\n\t};\n};\n\n/*global helpers */\n\nhelpers.formatRuleResult = function (ruleResult) {\n\t'use strict';\n\t\n\treturn {\n\t\tid: ruleResult.id,\n\t\tdescription: ruleResult.description,\n\t\thelp: ruleResult.help,\n\t\thelpUrl: ruleResult.helpUrl || null,\n\t\timpact: null,\n\t\ttags: ruleResult.tags,\n\t\tnodes: []\n\t};\n};\n\n/*global helpers */\nhelpers.splitResultsWithChecks = function (results) {\n\t'use strict';\n\treturn helpers.splitResults(results, helpers.formatChecks);\n};\n\n/*global helpers */\n\nhelpers.splitResults = function (results, nodeDataMapper) {\n\t'use strict';\n\n\tvar violations = [],\n\t\tpasses = [];\n\n\tresults.forEach(function (rr) {\n\n\t\tfunction mapNode(nodeData) {\n\t\t\tvar result = nodeData.result || rr.result;\n\t\t\tvar node = helpers.formatNode(nodeData.node);\n\t\t\tnode.impact = nodeData.impact || null;\n\n\t\t\treturn nodeDataMapper(node, nodeData, result);\n\t\t}\n\n\t\tvar failResult,\n\t\t\tpassResult = helpers.formatRuleResult(rr);\n\n\t\tfailResult = utils.clone(passResult);\n\t\tfailResult.impact = rr.impact || null;\n\n\t\tfailResult.nodes = rr.violations.map(mapNode);\n\t\tpassResult.nodes = rr.passes.map(mapNode);\n\n\t\tif (failResult.nodes.length) {\n\t\t\tviolations.push(failResult);\n\t\t}\n\t\tif (passResult.nodes.length) {\n\t\t\tpasses.push(passResult);\n\t\t}\n\t});\n\n\treturn {\n\t\tviolations: violations,\n\t\tpasses: passes,\n\t\turl: window.location.href,\n\t\ttimestamp: new Date()\n\t};\n};\n\n/*global helpers */\naxe.reporter('na', function (results, callback) {\n\t'use strict';\n\tvar na = results.filter(function (rr) {\n\t\treturn rr.violations.length === 0 && rr.passes.length === 0;\n\t}).map(helpers.formatRuleResult);\n\n\tvar formattedResults = helpers.splitResultsWithChecks(results);\n\tcallback({\n\t\tviolations: formattedResults.violations,\n\t\tpasses: formattedResults.passes,\n\t\tnotApplicable: na,\n\t\ttimestamp: formattedResults.timestamp,\n\t\turl: formattedResults.url\n\t});\n});\n\n/*global helpers */\naxe.reporter('no-passes', function (results, callback) {\n\t'use strict';\n\n\tvar formattedResults = helpers.splitResultsWithChecks(results);\n\tcallback({\n\t\tviolations: formattedResults.violations,\n\t\ttimestamp: formattedResults.timestamp,\n\t\turl: formattedResults.url\n\t});\n});\n\naxe.reporter('raw', function (results, callback) {\n\t'use strict';\n\tcallback(results);\n});\n\n/*global helpers */\n\naxe.reporter('v1', function (results, callback) {\n\t'use strict';\n\tvar formattedResults = helpers.splitResults(results, function (nodeResult, data, result) {\n\t\tif (result === axe.constants.result.FAIL) {\n\t\t\tnodeResult.failureSummary = helpers.failureSummary(data);\n\t\t}\n\n\t\treturn nodeResult;\n\t});\n\tcallback({\n\t\tviolations: formattedResults.violations,\n\t\tpasses: formattedResults.passes,\n\t\ttimestamp: formattedResults.timestamp,\n\t\turl: formattedResults.url\n\t});\n});\n\n/*global helpers */\n\n\naxe.reporter('v2', function (results, callback) {\n\t'use strict';\n\tvar formattedResults = helpers.splitResultsWithChecks(results);\n\tcallback({\n\t\tviolations: formattedResults.violations,\n\t\tpasses: formattedResults.passes,\n\t\ttimestamp: formattedResults.timestamp,\n\t\turl: formattedResults.url\n\t});\n}, true);\n\n/**\n * Helper to denote which checks are asyncronous and provide callbacks and pass data back to the CheckResult\n * @param  {CheckResult}   checkResult The target object\n * @param  {Function} callback    The callback to expose when `this.async()` is called\n * @return {Object}               Bound to `this` for a check's fn\n */\nutils.checkHelper = function checkHelper(checkResult, callback) {\n\t'use strict';\n\n\treturn {\n\t\tisAsync: false,\n\t\tasync: function () {\n\t\t\tthis.isAsync = true;\n\t\t\treturn function (result) {\n\t\t\t\tcheckResult.value = result;\n\t\t\t\tcallback(checkResult);\n\t\t\t};\n\t\t},\n\t\tdata: function (data) {\n\t\t\tcheckResult.data = data;\n\t\t},\n\t\trelatedNodes: function (nodes) {\n\t\t\tnodes = nodes instanceof Node ? [nodes] : utils.toArray(nodes);\n\t\t\tcheckResult.relatedNodes = nodes.map(function (element) {\n\t\t\t\treturn new utils.DqElement(element);\n\t\t\t});\n\t\t}\n\t};\n};\n\n\n/**\n * Sends a command to the sepecified frame\n * @param  {Element}  node       The frame element to send the message to\n * @param  {Object}   parameters Parameters to pass to the frame\n * @param  {Function} callback   Function to call when results from all frames have returned\n */\nutils.sendCommandToFrame = function(node, parameters, callback) {\n  'use strict';\n\n  var win = node.contentWindow;\n  if (!win) {\n    axe.log('Frame does not have a content window', node);\n    return callback({});\n  }\n\n  var timeout = setTimeout(function () {\n    timeout = setTimeout(function () {\n      axe.log('No response from frame: ', node);\n      callback(null);\n    }, 0);\n  }, 500);\n\n  utils.respondable(win, 'axe.ping', null, function () {\n    clearTimeout(timeout);\n    timeout = setTimeout(function () {\n      axe.log('Error returning results from frame: ', node);\n      callback({});\n      callback = null;\n    }, 30000);\n    utils.respondable(win, 'axe.start', parameters, function (data) {\n      if (callback) {\n        clearTimeout(timeout);\n        callback(data);\n      }\n    });\n  });\n\n};\n\n\n/**\n* Sends a message to frames to start analysis and collate results (via `mergeResults`)\n* @private\n* @param  {Context}   context  The resolved Context object\n* @param  {Object}   options   Options object (as passed to `runRules`)\n* @param  {Function} callback  Function to call when results from all frames have returned\n*/\nutils.collectResultsFromFrames = function collectResultsFromFrames(context, options, command, parameter, callback) {\n  'use strict';\n\n  var q = utils.queue();\n  var frames = context.frames;\n\n  function defer(frame) {\n    var params = {\n      options: options,\n      command: command,\n      parameter: parameter,\n      context: {\n        initiator: false,\n        page: context.page,\n        include: frame.include || [],\n        exclude: frame.exclude || []\n      }\n    };\n\n    q.defer(function (done) {\n      var node = frame.node;\n      utils.sendCommandToFrame(node, params, function (data) {\n        if (data) {\n          return done({\n            results: data,\n            frameElement: node,\n            frame: utils.getSelector(node)\n          });\n        }\n        done(null);\n      });\n    });\n  }\n\n  for (var i = 0, l = frames.length; i < l; i++) {\n    defer(frames[i]);\n  }\n\n  q.then(function (data) {\n    callback(utils.mergeResults(data));\n  });\n};\n\n\n/**\n * Wrapper for Node#contains; PhantomJS does not support Node#contains and erroneously reports that it does\n * @param  {HTMLElement} node      The candidate container node\n * @param  {HTMLElement} otherNode The node to test is contained by `node`\n * @return {Boolean}           Whether `node` contains `otherNode`\n */\nutils.contains = function (node, otherNode) {\n\t//jshint bitwise: false\n\t'use strict';\n\n\tif (typeof node.contains === 'function') {\n\t\treturn node.contains(otherNode);\n\t}\n\n\treturn !!(node.compareDocumentPosition(otherNode) & 16);\n\n};\n/*exported DqElement */\n\nfunction truncate(str, maxLength) {\n\t'use strict';\n\n\tmaxLength = maxLength || 300;\n\n\tif (str.length > maxLength) {\n\t\tvar index = str.indexOf('>');\n\t\tstr = str.substring(0, index + 1);\n\t}\n\n\treturn str;\n}\n\nfunction getSource (element) {\n\t'use strict';\n\n\tvar source = element.outerHTML;\n\tif (!source && typeof XMLSerializer === 'function') {\n\t\tsource = new XMLSerializer().serializeToString(element);\n\t}\n\treturn truncate(source || '');\n}\n\n/**\n * \"Serialized\" `HTMLElement`. It will calculate the CSS selector,\n * grab the source (outerHTML) and offer an array for storing frame paths\n * @param {HTMLElement} element The element to serialize\n * @param {Object} spec Properties to use in place of the element when instantiated on Elements from other frames\n */\nfunction DqElement(element, spec) {\n\t'use strict';\n\tspec = spec || {};\n\n\t/**\n\t * A unique CSS selector for the element\n\t * @type {String}\n\t */\n\tthis.selector = spec.selector || [utils.getSelector(element)];\n\n\t/**\n\t * The generated HTML source code of the element\n\t * @type {String}\n\t */\n\tthis.source = spec.source !== undefined ? spec.source : getSource(element);\n\n\t/**\n\t * The element which this object is based off or the containing frame, used for sorting.\n\t * Excluded in toJSON method.\n\t * @type {HTMLElement}\n\t */\n\tthis.element = element;\n}\n\nDqElement.prototype.toJSON = function () {\n\t'use strict';\n\treturn {\n\t\tselector: this.selector,\n\t\tsource: this.source\n\t};\n};\n\nutils.DqElement = DqElement;\n\n\n/**\n * Extends metadata onto result object and executes any functions.  Will not deeply extend.\n * @param  {Object} to   The target of the extend\n * @param  {Object} from Metadata to extend\n * @param  {Array}  blacklist property names to exclude from resulting object\n */\nutils.extendBlacklist = function (to, from, blacklist) {\n\t'use strict';\n\tblacklist = blacklist || [];\n\n\tfor (var i in from) {\n\t\tif (from.hasOwnProperty(i) && blacklist.indexOf(i) === -1) {\n\t\t\tto[i] = from[i];\n\t\t}\n\t}\n\n\treturn to;\n};\n\n\n/**\n * Extends metadata onto result object and executes any functions\n * @param  {Object} to   The target of the extend\n * @param  {Object} from Metadata to extend\n */\nutils.extendMetaData = function (to, from) {\n\t'use strict';\n\n\tfor (var i in from) {\n\t\tif (from.hasOwnProperty(i)) {\n\t\t\tif (typeof from[i] === 'function') {\n\t\t\t\ttry {\n\t\t\t\t\tto[i] = from[i](to);\n\t\t\t\t} catch (e) {\n\t\t\t\t\tto[i] = null;\n\t\t\t\t}\n\t\t\t} else {\n\t\t\t\tto[i] = from[i];\n\t\t\t}\n\t\t}\n\t}\n};\n\n\nfunction raiseMetadata(obj, checks) {\n\t'use strict';\n\n\tObject.keys(axe.constants.raisedMetadata).forEach(function (key) {\n\t\tvar collection = axe.constants.raisedMetadata[key];\n\t\tvar highestIndex = checks.reduce(function (prevIndex, current) {\n\t\t  var currentIndex = collection.indexOf(current[key]);\n\t\t  return currentIndex > prevIndex ? currentIndex : prevIndex;\n\t\t}, -1);\n\t\tif (collection[highestIndex]) {\n\t\t\tobj[key] = collection[highestIndex];\n\t\t}\n\t});\n\n}\n\n/**\n * Calculates the result (PASS or FAIL) of a Node (node-level) or an entire Rule (page-level)\n * @private\n * @param  {Array} checks  Array of checks to calculate the result of\n * @return {String}        Either \"PASS\" or \"FAIL\"\n */\nfunction calculateCheckResult(failingChecks) {\n\t'use strict';\n\tvar isFailing = failingChecks.any.length || failingChecks.all.length || failingChecks.none.length;\n\n\treturn isFailing ? axe.constants.result.FAIL : axe.constants.result.PASS;\n}\n\n/**\n * Iterates and calculates the results of each Node and then rolls the result up to the parent RuleResult\n * @private\n * @param  {RuleResult} ruleResult The RuleResult to test\n */\nfunction calculateRuleResult(ruleResult) {\n\t'use strict';\n\tfunction checkMap(check) {\n\t\treturn utils.extendBlacklist({}, check, ['result']);\n\t}\n\n\n\tvar newRuleResult = utils.extendBlacklist({\n\t\tviolations: [],\n\t\tpasses: []\n\t}, ruleResult, ['nodes']);\n\n\truleResult.nodes.forEach(function (detail) {\n\n\t\tvar failingChecks = utils.getFailingChecks(detail);\n\t\tvar result = calculateCheckResult(failingChecks);\n\n\t\tif (result === axe.constants.result.FAIL) {\n\t\t\traiseMetadata(detail, utils.getAllChecks(failingChecks));\n\t\t\tdetail.any = failingChecks.any.map(checkMap);\n\t\t\tdetail.all = failingChecks.all.map(checkMap);\n\t\t\tdetail.none = failingChecks.none.map(checkMap);\n\t\t\tnewRuleResult.violations.push(detail);\n\t\t\treturn;\n\t\t}\n\n\t\tdetail.any = detail.any.filter(function (check) {\n\t\t\treturn check.result;\n\t\t}).map(checkMap);\n\t\t// no need to filter `all` or `none` since we know they all pass\n\t\tdetail.all = detail.all.map(checkMap);\n\t\tdetail.none = detail.none.map(checkMap);\n\n\t\tnewRuleResult.passes.push(detail);\n\t});\n\traiseMetadata(newRuleResult, newRuleResult.violations);\n\n\tnewRuleResult.result = newRuleResult.violations.length ? axe.constants.result.FAIL :\n\t\t(newRuleResult.passes.length ? axe.constants.result.PASS : newRuleResult.result);\n\n\treturn newRuleResult;\n}\n\nutils.getFailingChecks = function (detail) {\n\t'use strict';\n\n\tvar any = detail.any.filter(function (check) {\n\t\treturn !check.result;\n\t});\n\treturn {\n\t\tall: detail.all.filter(function (check) {\n\t\t\treturn !check.result;\n\t\t}),\n\t\tany: any.length === detail.any.length ? any : [],\n\t\tnone: detail.none.filter(function (check) {\n\t\t\treturn !!check.result;\n\t\t})\n\t};\n};\n\n\n/**\n * Calculates the result of a Rule based on its types and the result of its child Checks\n * @param  {RuleResult} ruleResult The RuleResult to calculate the result of\n */\nutils.finalizeRuleResult = function (ruleResult) {\n\t'use strict';\n\n\tutils.publishMetaData(ruleResult);\n\treturn calculateRuleResult(ruleResult);\n};\n\n\n/**\n * Iterates an array of objects looking for a property with a specific value\n * @param  {Array} array  The array of objects to iterate\n * @param  {String} key   The property name to test against\n * @param  {Mixed} value  The value to find\n * @return {Object}       The first matching object or `undefined` if no match\n */\nutils.findBy = function (array, key, value) {\n\t'use strict';\n\tarray = array || [];\n\n\tvar index, length;\n\tfor (index = 0, length = array.length; index < length; index++) {\n\t\tif (array[index][key] === value) {\n\t\t\treturn array[index];\n\t\t}\n\t}\n};\n\n/**\n * Gets all Checks (or CheckResults) for a given Rule or RuleResult\n * @param {RuleResult|Rule} rule\n */\nutils.getAllChecks = function getAllChecks(object) {\n\t'use strict';\n\tvar result = [];\n\treturn result.concat(object.any || []).concat(object.all || []).concat(object.none || []);\n};\n\n\n/**\n * Determines which CheckOption to use, either defined on the rule options, global check options or the check itself\n * @param  {Check} check    The Check object\n * @param  {String} ruleID  The ID of the rule\n * @param  {Object} options Options object as passed to main API\n * @return {Object}         The resolved object with `options` and `enabled` keys\n */\nutils.getCheckOption = function (check, ruleID, options) {\n\t'use strict';\n\tvar ruleCheckOption = ((options.rules && options.rules[ruleID] || {}).checks || {})[check.id];\n\tvar checkOption = (options.checks || {})[check.id];\n\n\tvar enabled = check.enabled;\n\tvar opts = check.options;\n\n\tif (checkOption) {\n\t\tif (checkOption.hasOwnProperty('enabled')) {\n\t\t\tenabled = checkOption.enabled;\n\t\t}\n\t\tif (checkOption.hasOwnProperty('options')) {\n\t\t\topts = checkOption.options;\n\t\t}\n\n\t}\n\n\tif (ruleCheckOption) {\n\t\tif (ruleCheckOption.hasOwnProperty('enabled')) {\n\t\t\tenabled = ruleCheckOption.enabled;\n\t\t}\n\t\tif (ruleCheckOption.hasOwnProperty('options')) {\n\t\t\topts = ruleCheckOption.options;\n\t\t}\n\t}\n\n\treturn {\n\t\tenabled: enabled,\n\t\toptions: opts\n\t};\n};\n/**\n * Gets the index of element siblings that have the same nodeName\n * Intended for use with the CSS psuedo-class `:nth-of-type()` and xpath node index\n * @param  {HTMLElement} element The element to test\n * @return {Number}         The number of preceeding siblings with the same nodeName\n * @private\n */\nfunction nthOfType(element) {\n\t'use strict';\n\n\tvar index = 1,\n\t\ttype = element.nodeName;\n\n\t/*jshint boss:true */\n\twhile (element = element.previousElementSibling) {\n\t\tif (element.nodeName === type) {\n\t\t\tindex++;\n\t\t}\n\t}\n\n\treturn index;\n}\n\n/**\n * Checks if an element has siblings with the same selector\n * @param  {HTMLElement} node     The element to test\n * @param  {String} selector The CSS selector to test\n * @return {Boolean}          Whether any of element's siblings matches selector\n * @private\n */\nfunction siblingsHaveSameSelector(node, selector) {\n\t'use strict';\n\n\tvar index, sibling,\n\t\tsiblings = node.parentNode.children;\n\n\tif (!siblings) {\n\t\treturn false;\n\t}\n\n\tvar length = siblings.length;\n\n\tfor (index = 0; index < length; index++) {\n\t\tsibling = siblings[index];\n\t\tif (sibling !== node && utils.matchesSelector(sibling, selector)) {\n\t\t\treturn true;\n\t\t}\n\t}\n\treturn false;\n}\n\n\n/**\n * Gets a unique CSS selector\n * @param  {HTMLElement} node The element to get the selector for\n * @return {String}      Unique CSS selector for the node\n */\nutils.getSelector = function getSelector(node) {\n\t//jshint maxstatements: 21\n\t'use strict';\n\n\tfunction escape(p) {\n\t\treturn utils.escapeSelector(p);\n\t}\n\n\tvar parts = [], part;\n\n\twhile (node.parentNode) {\n\t\tpart = '';\n\n\t\tif (node.id && document.querySelectorAll('#' + utils.escapeSelector(node.id)).length === 1) {\n\t\t\tparts.unshift('#' + utils.escapeSelector(node.id));\n\t\t\tbreak;\n\t\t}\n\n\t\tif (node.className && typeof node.className === 'string') {\n\t\t\tpart = '.' + node.className.trim().split(/\\s+/).map(escape).join('.');\n\t\t\tif (part === '.' || siblingsHaveSameSelector(node, part)) {\n\t\t\t\tpart = '';\n\t\t\t}\n\t\t}\n\n\t\tif (!part) {\n\t\t\tpart = utils.escapeSelector(node.nodeName).toLowerCase();\n\t\t\tif (part === 'html' || part === 'body') {\n\t\t\t\tparts.unshift(part);\n\t\t\t\tbreak;\n\t\t\t}\n\t\t\tif (siblingsHaveSameSelector(node, part)) {\n\t\t\t\tpart += ':nth-of-type(' + nthOfType(node) + ')';\n\t\t\t}\n\n\t\t}\n\n\t\tparts.unshift(part);\n\n\t\tnode = node.parentNode;\n\t}\n\n\treturn parts.join(' > ');\n\n};\n\n/*exported injectStyle */\n\nvar styleSheet;\nfunction injectStyle(style) {\n\t'use strict';\n\n\tif (styleSheet && styleSheet.parentNode) {\n\t\tstyleSheet.parentNode.removeChild(styleSheet);\n\t\tstyleSheet = null;\n\t}\n\tif (!style) {\n\t\treturn;\n\t}\n\n\tvar head = document.head || document.getElementsByTagName('head')[0];\n\tstyleSheet = document.createElement('style');\n\tstyleSheet.type = 'text/css';\n\n\tif (styleSheet.styleSheet === undefined) { // Not old IE\n\t\tstyleSheet.appendChild(document.createTextNode(style));\n\t} else {\n\t\tstyleSheet.styleSheet.cssText = style;\n\t}\n\n\thead.appendChild(styleSheet);\n\n\treturn styleSheet;\n}\n\n\n\n/**\n * Determine whether an element is visible\n *\n * @param {HTMLElement} el The HTMLElement\n * @return {Boolean} The element's visibilty status\n */\nutils.isHidden = function isHidden(el, recursed) {\n\t'use strict';\n\n\t// 9 === Node.DOCUMENT\n\tif (el.nodeType === 9) {\n\t\treturn false;\n\t}\n\n\tvar style = window.getComputedStyle(el, null);\n\n\tif (!style || (!el.parentNode || (style.getPropertyValue('display') === 'none' ||\n\n\t\t\t(!recursed &&\n\t\t\t\t// visibility is only accurate on the first element\n\t\t\t\t(style.getPropertyValue('visibility') === 'hidden')) ||\n\n\t\t\t(el.getAttribute('aria-hidden') === 'true')))) {\n\n\t\treturn true;\n\t}\n\n\treturn utils.isHidden(el.parentNode, true);\n\n};\n\n\n/**\n* Adds the owning frame's CSS selector onto each instance of DqElement\n* @private\n* @param  {Array} resultSet `nodes` array on a `RuleResult`\n* @param  {HTMLElement} frameElement  The frame element\n* @param  {String} frameSelector     Unique CSS selector for the frame\n*/\nfunction pushFrame(resultSet, frameElement, frameSelector) {\n  'use strict';\n  resultSet.forEach(function (res) {\n    res.node.selector.unshift(frameSelector);\n    res.node = new utils.DqElement(frameElement, res.node);\n    var checks = utils.getAllChecks(res);\n    if (checks.length) {\n      checks.forEach(function (check) {\n        check.relatedNodes.forEach(function (node) {\n          node.selector.unshift(frameSelector);\n          node = new utils.DqElement(frameElement, node);\n        });\n      });\n    }\n  });\n}\n\n/**\n* Adds `to` to `from` and then re-sorts by DOM order\n* @private\n* @param  {Array} target  `nodes` array on a `RuleResult`\n* @param  {Array} to   `nodes` array on a `RuleResult`\n* @return {Array}      The merged and sorted result\n*/\nfunction spliceNodes(target, to) {\n  'use strict';\n\n  var firstFromFrame = to[0].node,\n  sorterResult, t;\n  for (var i = 0, l = target.length; i < l; i++) {\n    t = target[i].node;\n    sorterResult = utils.nodeSorter(t.element, firstFromFrame.element);\n    if (sorterResult > 0 || (sorterResult === 0 && firstFromFrame.selector.length < t.selector.length)) {\n      target.splice.apply(target, [i, 0].concat(to));\n      return;\n    }\n  }\n\n  target.push.apply(target, to);\n}\n\nfunction normalizeResult(result) {\n  'use strict';\n\n  if (!result || !result.results) {\n    return null;\n  }\n\n  if (!Array.isArray(result.results)) {\n    return [result.results];\n  }\n\n  if (!result.results.length) {\n    return null;\n  }\n\n  return result.results;\n\n}\n\n/**\n* Merges one or more RuleResults (possibly from different frames) into one RuleResult\n* @private\n* @param  {Array} frameResults  Array of objects including the RuleResults as `results` and frame as `frame`\n* @return {Array}              The merged RuleResults; should only have one result per rule\n*/\nutils.mergeResults = function mergeResults(frameResults) {\n  'use strict';\n  var result = [];\n  frameResults.forEach(function (frameResult) {\n    var results = normalizeResult(frameResult);\n    if (!results || !results.length) {\n      return;\n    }\n\n    results.forEach(function (ruleResult) {\n      if (ruleResult.nodes && frameResult.frame) {\n        pushFrame(ruleResult.nodes, frameResult.frameElement, frameResult.frame);\n      }\n\n      var res = utils.findBy(result, 'id', ruleResult.id);\n      if (!res) {\n        result.push(ruleResult);\n      } else {\n        if (ruleResult.nodes.length) {\n          spliceNodes(res.nodes, ruleResult.nodes);\n        }\n      }\n    });\n  });\n  return result;\n};\n\n/**\n * Array#sort callback to sort nodes by DOM order\n * @private\n * @param  {Node} a\n * @param  {Node} b\n * @return {Integer}   @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Sort\n */\nutils.nodeSorter = function nodeSorter(a, b) {\n\t/*jshint bitwise: false */\n\n\t'use strict';\n\n\tif (a === b) {\n\t\treturn 0;\n\t}\n\n\tif (a.compareDocumentPosition(b) & 4) { // a before b\n\t\treturn -1;\n\t}\n\n\treturn 1; // b before a\n\n};\n\n\n/**\n * Publish metadata from axe._audit.data\n * @param  {RuleResult} result Result to publish to\n * @private\n */\nutils.publishMetaData = function (ruleResult) {\n\t'use strict';\n\n\tfunction extender(shouldBeTrue) {\n\t\treturn function (check) {\n\t\t\tvar sourceData = checksData[check.id] || {};\n\t\t\tvar messages = sourceData.messages || {};\n\t\t\tvar data = utils.extendBlacklist({}, sourceData, ['messages']);\n\t\t\tdata.message = check.result === shouldBeTrue ? messages.pass : messages.fail;\n\t\t\tutils.extendMetaData(check, data);\n\t\t};\n\t}\n\n\tvar checksData = axe._audit.data.checks || {};\n\tvar rulesData = axe._audit.data.rules || {};\n\tvar rule = utils.findBy(axe._audit.rules, 'id', ruleResult.id) || {};\n\n\truleResult.tags = utils.clone(rule.tags || []);\n\n\tvar shouldBeTrue = extender(true);\n\tvar shouldBeFalse = extender(false);\n\truleResult.nodes.forEach(function (detail) {\n\t\tdetail.any.forEach(shouldBeTrue);\n\t\tdetail.all.forEach(shouldBeTrue);\n\t\tdetail.none.forEach(shouldBeFalse);\n\t});\n\tutils.extendMetaData(ruleResult, utils.clone(rulesData[ruleResult.id] || {}));\n};\n\n(function () {\n\t'use strict';\n\tfunction noop() {}\n\n\t/**\n\t * Create an asyncronous \"queue\", list of functions to be invoked in parallel, but not necessarily returned in order\n\t * @return {Queue} The newly generated \"queue\"\n\t */\n\tfunction queue() {\n\t\tvar tasks = [],\n\t\t\tstarted = 0,\n\t\t\tremaining = 0, // number of tasks not yet finished\n\t\t\tawt = noop;\n\n\t\tfunction pop() {\n\t\t\tvar length = tasks.length;\n\t\t\tfor (; started < length; started++) {\n\t\t\t\tvar task = tasks[started],\n\t\t\t\t\tfn = task.shift();\n\n\t\t\t\ttask.push(callback(started));\n\t\t\t\tfn.apply(null, task);\n\t\t\t}\n\t\t}\n\n\t\tfunction callback(i) {\n\t\t\treturn function (r) {\n\t\t\t\ttasks[i] = r;\n\t\t\t\tif (!--remaining) {\n\t\t\t\t\tnotify();\n\t\t\t\t}\n\t\t\t};\n\t\t}\n\n\t\tfunction notify() {\n\t\t\tawt(tasks);\n\t\t}\n\n\t\treturn {\n\t\t\t/**\n\t\t\t * Defer a function that may or may not run asynchronously.\n\t\t\t *\n\t\t\t * First parameter should be the function to execute with subsequent\n\t\t\t * parameters being passed as arguments to that function\n\t\t\t */\n\t\t\tdefer: function (fn) {\n\t\t\t\ttasks.push([fn]);\n\t\t\t\t++remaining;\n\t\t\t\tpop();\n\t\t\t},\n\t\t\t/**\n\t\t\t * The callback to execute once all \"deferred\" functions have completed.  Will only be invoked once.\n\t\t\t * @param  {Function} f The callback, receives an array of the return/callbacked\n\t\t\t * values of each of the \"deferred\" functions\n\t\t\t */\n\t\t\tthen: function (f) {\n\t\t\t\tawt = f;\n\t\t\t\tif (!remaining) {\n\t\t\t\t\tnotify();\n\t\t\t\t}\n\t\t\t},\n\t\t\t/**\n\t\t\t * Abort the \"queue\" and prevent `then` function from firing\n\t\t\t * @param  {Function} fn The callback to execute; receives an array of the results which have completed\n\t\t\t */\n\t\t\tabort: function (fn) {\n\t\t\t\tawt = noop;\n\t\t\t\tfn(tasks);\n\t\t\t}\n\t\t};\n\t}\n\n\tutils.queue = queue;\n})();\n\n/*global uuid */\n(function (exports) {\n\t'use strict';\n\tvar messages = {},\n\t\tsubscribers = {};\n\n\t/**\n\t * Verify the received message is from the \"respondable\" module\n\t * @private\n\t * @param  {Object} postedMessage The message received via postMessage\n\t * @return {Boolean}              `true` if the message is verified from respondable\n\t */\n\tfunction verify(postedMessage) {\n\t\treturn typeof postedMessage === 'object' && typeof postedMessage.uuid === 'string' &&\n\t\t\tpostedMessage._respondable === true;\n\t}\n\n\t/**\n\t * Posts the message to correct frame.\n\t * This abstraction necessary because IE9 & 10 do not support posting Objects; only strings\n\t * @private\n\t * @param  {Window}   win      The `window` to post the message to\n\t * @param  {String}   topic    The topic of the message\n\t * @param  {Object}   message  The message content\n\t * @param  {String}   uuid     The UUID, or pseudo-unique ID of the message\n\t * @param  {Function} callback The function to invoke when/if the message is responded to\n\t */\n\tfunction post(win, topic, message, uuid, callback) {\n\n\t\tvar data = {\n\t\t\tuuid: uuid,\n\t\t\ttopic: topic,\n\t\t\tmessage: message,\n\t\t\t_respondable: true\n\t\t};\n\n\t\tmessages[uuid] = callback;\n\t\twin.postMessage(JSON.stringify(data), '*');\n\t}\n\n\t/**\n\t * Post a message to a window who may or may not respond to it.\n\t * @param  {Window}   win      The window to post the message to\n\t * @param  {String}   topic    The topic of the message\n\t * @param  {Object}   message  The message content\n\t * @param  {Function} callback The function to invoke when/if the message is responded to\n\t */\n\tfunction respondable(win, topic, message, callback) {\n\t\tvar id = uuid.v1();\n\t\tpost(win, topic, message, id, callback);\n\t}\n\n\t/**\n\t * Subscribe to messages sent via the `respondable` module.\n\t * @param  {String}   topic    The topic to listen to\n\t * @param  {Function} callback The function to invoke when a message is received\n\t */\n\trespondable.subscribe = function (topic, callback) {\n\t\tsubscribers[topic] = callback;\n\t};\n\n\t/**\n\t * Publishes the \"respondable\" message to the appropriate subscriber\n\t * @private\n\t * @param  {Event} event The event object of the postMessage\n\t * @param  {Object} data  The data sent with the message\n\t */\n\tfunction publish(event, data) {\n\t\tvar topic = data.topic,\n\t\t\tmessage = data.message,\n\t\t\tsubscriber = subscribers[topic];\n\t\tif (subscriber) {\n\t\t\tsubscriber(message, createResponder(event.source, null, data.uuid));\n\t\t}\n\t}\n\n\t/**\n\t * Helper closure to create a function that may be used to respond to a message\n\t * @private\n\t * @param  {Window} source The window from which the message originated\n\t * @param  {String} topic  The topic of the message\n\t * @param  {String} uuid   The \"unique\" ID of the original message\n\t * @return {Function}      A function that may be invoked to respond to the message\n\t */\n\tfunction createResponder(source, topic, uuid) {\n\t\treturn function (message, callback) {\n\t\t\tpost(source, topic, message, uuid, callback);\n\t\t};\n\t}\n\n\twindow.addEventListener('message', function (e) {\n\n\t\tif (typeof e.data !== 'string') {\n\t\t\treturn;\n\t\t}\n\n\t\tvar data;\n\t\ttry {\n\t\t\tdata = JSON.parse(e.data);\n\t\t} catch(ex) {}\n\n\t\tif (!verify(data)) {\n\t\t\treturn;\n\t\t}\n\n\t\tvar uuid = data.uuid;\n\t\tif (messages[uuid]) {\n\t\t\tmessages[uuid](data.message, createResponder(e.source, data.topic, uuid));\n\t\t\tmessages[uuid] = null;\n\t\t}\n\n\t\tpublish(e, data);\n\t}, false);\n\n\texports.respondable = respondable;\n\n}(utils));\n\n\n/**\n * Determines whether a rule should run\n * @param  {Rule}    rule     The rule to test\n * @param  {Context} context  The context of the Audit\n * @param  {Object}  options  Options object\n * @return {Boolean}\n */\nutils.ruleShouldRun = function (rule, context, options) {\n\t'use strict';\n\tif (rule.pageLevel && !context.page) {\n\t\treturn false;\n\t}\n\n\tvar runOnly = options.runOnly,\n\t\truleOptions = (options.rules || {})[rule.id];\n\n\tif (runOnly) {\n\t\tif (runOnly.type === 'rule') {\n\t\t\treturn runOnly.values.indexOf(rule.id) !== -1;\n\t\t}\n\n\t\treturn !!(runOnly.values || []).filter(function (item) {\n\t\t\treturn rule.tags.indexOf(item) !== -1;\n\t\t}).length;\n\t}\n\n\tif ((ruleOptions && ruleOptions.hasOwnProperty('enabled')) ? !ruleOptions.enabled : !rule.enabled) {\n\t\treturn false;\n\t}\n\n\treturn true;\n};\n/**\n * Get the deepest node in a given collection\n * @private\n * @param  {Array} collection Array of nodes to test\n * @return {Node}             The deepest node\n */\nfunction getDeepest(collection) {\n\t'use strict';\n\n\treturn collection.sort(function (a, b) {\n\t\tif (utils.contains(a, b)) {\n\t\t\treturn 1;\n\t\t}\n\t\treturn -1;\n\t})[0];\n\n}\n\n/**\n * Determines if a node is included or excluded in a given context\n * @private\n * @param  {Node}  node     The node to test\n * @param  {Object}  context \"Resolved\" context object, @see resolveContext\n * @return {Boolean}         [description]\n */\nfunction isNodeInContext(node, context) {\n\t'use strict';\n\n\tvar include = context.include && getDeepest(context.include.filter(function (candidate) {\n\t\treturn utils.contains(candidate, node);\n\t}));\n\tvar exclude = context.exclude && getDeepest(context.exclude.filter(function (candidate) {\n\t\treturn utils.contains(candidate, node);\n\t}));\n\tif ((!exclude && include) || (exclude && utils.contains(exclude, include))) {\n\t\treturn true;\n\t}\n\treturn false;\n}\n\n/**\n * Pushes unique nodes that are in context to an array\n * @private\n * @param  {Array} result  The array to push to\n * @param  {Array} nodes   The list of nodes to push\n * @param  {Object} context The \"resolved\" context object, @see resolveContext\n */\nfunction pushNode(result, nodes, context) {\n\t'use strict';\n\n\tfor (var i = 0, l = nodes.length; i < l; i++) {\n\t\tif (result.indexOf(nodes[i]) === -1 && isNodeInContext(nodes[i], context)) {\n\t\t\tresult.push(nodes[i]);\n\t\t}\n\t}\n}\n\n/**\n * Selects elements which match `select` that are included and excluded via the `Context` object\n * @param  {String} selector  CSS selector of the HTMLElements to select\n * @param  {Context} context  The \"resolved\" context object, @see Context\n * @return {Array}            Matching nodes sorted by DOM order\n */\nutils.select = function select(selector, context) {\n\t'use strict';\n\n\tvar result = [], candidate;\n\tfor (var i = 0, l = context.include.length; i < l; i++) {\n\t\tcandidate = context.include[i];\n\t\tif (candidate.nodeType === candidate.ELEMENT_NODE && utils.matchesSelector(candidate, selector)) {\n\t\t\tpushNode(result, [candidate], context);\n\t\t}\n\t\tpushNode(result, candidate.querySelectorAll(selector), context);\n\t}\n\n\treturn result.sort(utils.nodeSorter);\n};\n\n\n/**\n * Converts array-like (numerical indicies and `length` property) structures to actual, real arrays\n * @param  {Mixed} thing Array-like thing to convert\n * @return {Array}\n */\nutils.toArray = function (thing) {\n\t'use strict';\n\treturn Array.prototype.slice.call(thing);\n};\naxe._load({\"data\":{\"rules\":{\"accesskeys\":{\"description\":\"Ensures every accesskey attribute value is unique\",\"help\":\"accesskey attribute value must be unique\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/accesskeys\"},\"area-alt\":{\"description\":\"Ensures <area> elements of image maps have alternate text\",\"help\":\"Active <area> elements must have alternate text\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/area-alt\"},\"aria-allowed-attr\":{\"description\":\"Ensures ARIA attributes are allowed for an element's role\",\"help\":\"Elements must only use allowed ARIA attributes\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-allowed-attr\"},\"aria-required-attr\":{\"description\":\"Ensures elements with ARIA roles have all required ARIA attributes\",\"help\":\"Required ARIA attributes must be provided\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-required-attr\"},\"aria-required-children\":{\"description\":\"Ensures elements with an ARIA role that require child roles contain them\",\"help\":\"Certain ARIA roles must contain particular children\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-required-children\"},\"aria-required-parent\":{\"description\":\"Ensures elements with an ARIA role that require parent roles are contained by them\",\"help\":\"Certain ARIA roles must be contained by particular parents\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-required-parent\"},\"aria-roles\":{\"description\":\"Ensures all elements with a role attribute use a valid value\",\"help\":\"ARIA roles used must conform to valid values\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-roles\"},\"aria-valid-attr-value\":{\"description\":\"Ensures all ARIA attributes have valid values\",\"help\":\"ARIA attributes must conform to valid values\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-valid-attr-value\"},\"aria-valid-attr\":{\"description\":\"Ensures attributes that begin with aria- are valid ARIA attributes\",\"help\":\"ARIA attributes must conform to valid names\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/aria-valid-attr\"},\"audio-caption\":{\"description\":\"Ensures <audio> elements have captions\",\"help\":\"<audio> elements must have a captions track\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/audio-caption\"},\"blink\":{\"description\":\"Ensures <blink> elements are not used\",\"help\":\"<blink> elements are deprecated and must not be used\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/blink\"},\"button-name\":{\"description\":\"Ensures buttons have discernible text\",\"help\":\"Buttons must have discernible text\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/button-name\"},\"bypass\":{\"description\":\"Ensures each page has at least one mechanism for a user to bypass navigation and jump straight to the content\",\"help\":\"Page must have means to bypass repeated blocks\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/bypass\"},\"checkboxgroup\":{\"description\":\"Ensures related <input type=\\\"checkbox\\\"> elements have a group and that that group designation is consistent\",\"help\":\"Checkbox inputs with the same name attribute value must be part of a group\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/checkboxgroup\"},\"color-contrast\":{\"description\":\"Ensures the contrast between foreground and background colors meets WCAG 2 AA contrast ratio thresholds\",\"help\":\"Elements must have sufficient color contrast\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/color-contrast\"},\"data-table\":{\"description\":\"Ensures data tables are marked up semantically and have the correct header structure\",\"help\":\"Data tables should be marked up properly\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/data-table\"},\"definition-list\":{\"description\":\"Ensures <dl> elements are structured correctly\",\"help\":\"<dl> elements must only directly contain properly-ordered <dt> and <dd> groups, <script> or <template> elements\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/definition-list\"},\"dlitem\":{\"description\":\"Ensures <dt> and <dd> elements are contained by a <dl>\",\"help\":\"<dt> and <dd> elements must be contained by a <dl>\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/dlitem\"},\"document-title\":{\"description\":\"Ensures each HTML document contains a non-empty <title> element\",\"help\":\"Documents must have <title> element to aid in navigation\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/document-title\"},\"duplicate-id\":{\"description\":\"Ensures every id attribute value is unique\",\"help\":\"id attribute value must be unique\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/duplicate-id\"},\"empty-heading\":{\"description\":\"Ensures headings have discernible text\",\"help\":\"Headings must not be empty\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/empty-heading\"},\"frame-title\":{\"description\":\"Ensures <iframe> and <frame> elements contain a unique and non-empty title attribute\",\"help\":\"Frames must have unique title attribute\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/frame-title\"},\"heading-order\":{\"description\":\"Ensures the order of headings is semantically correct\",\"help\":\"Heading levels should only increase by one\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/heading-order\"},\"html-lang\":{\"description\":\"Ensures every HTML document has a lang attribute and its value is valid\",\"help\":\"<html> element must have a valid lang attribute\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/html-lang\"},\"image-alt\":{\"description\":\"Ensures <img> elements have alternate text or a role of none or presentation\",\"help\":\"Images must have alternate text\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/image-alt\"},\"input-image-alt\":{\"description\":\"Ensures <input type=\\\"image\\\"> elements have alternate text\",\"help\":\"Image buttons must have alternate text\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/input-image-alt\"},\"label-title-only\":{\"description\":\"Ensures that every form element is not solely labeled using the title or aria-describedby attributes\",\"help\":\"Form elements should have a visible label\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/label-title-only\"},\"label\":{\"description\":\"Ensures every form element has a label\",\"help\":\"Form elements must have labels\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/label\"},\"layout-table\":{\"description\":\"Ensures presentational <table> elements do not use <th>, <caption> elements or the summary attribute\",\"help\":\"Layout tables must not use data table elements\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/layout-table\"},\"link-name\":{\"description\":\"Ensures links have discernible text\",\"help\":\"Links must have discernible text\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/link-name\"},\"list\":{\"description\":\"Ensures that lists are structured correctly\",\"help\":\"<ul> and <ol> must only directly contain <li>, <script> or <template> elements\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/list\"},\"listitem\":{\"description\":\"Ensures <li> elements are used semantically\",\"help\":\"<li> elements must be contained in a <ul> or <ol>\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/listitem\"},\"marquee\":{\"description\":\"Ensures <marquee> elements are not used\",\"help\":\"<marquee> elements are deprecated and must not be used\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/marquee\"},\"meta-refresh\":{\"description\":\"Ensures <meta http-equiv=\\\"refresh\\\"> is not used\",\"help\":\"Timed refresh must not exist\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/meta-refresh\"},\"meta-viewport\":{\"description\":\"Ensures <meta name=\\\"viewport\\\"> does not disable text scaling and zooming\",\"help\":\"Zooming and scaling must not be disabled\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/meta-viewport\"},\"object-alt\":{\"description\":\"Ensures <object> elements have alternate text\",\"help\":\"<object> elements must have alternate text\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/object-alt\"},\"radiogroup\":{\"description\":\"Ensures related <input type=\\\"radio\\\"> elements have a group and that the group designation is consistent\",\"help\":\"Radio inputs with the same name attribute value must be part of a group\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/radiogroup\"},\"region\":{\"description\":\"Ensures all content is contained within a landmark region\",\"help\":\"Content should be contained in a landmark region\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/region\"},\"scope\":{\"description\":\"Ensures the scope attribute is used correctly on tables\",\"help\":\"scope attribute should be used correctly\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/scope\"},\"server-side-image-map\":{\"description\":\"Ensures that server-side image maps are not used\",\"help\":\"Server-side image maps must not be used\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/server-side-image-map\"},\"skip-link\":{\"description\":\"Ensures the first link on the page is a skip link\",\"help\":\"The page should have a skip link as its first link\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/skip-link\"},\"tabindex\":{\"description\":\"Ensures tabindex attribute values are not greater than 0\",\"help\":\"Elements should not have tabindex greater than zero\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/tabindex\"},\"valid-lang\":{\"description\":\"Ensures lang attributes have valid values\",\"help\":\"lang attribute must have a valid value\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/valid-lang\"},\"video-caption\":{\"description\":\"Ensures <video> elements have captions\",\"help\":\"<video> elements must have captions\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/video-caption\"},\"video-description\":{\"description\":\"Ensures <video> elements have audio descriptions\",\"help\":\"<video> elements must have an audio description track\",\"helpUrl\":\"https://dequeuniversity.com/rules/axe/1.1/video-description\"}},\"checks\":{\"accesskeys\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Accesskey attribute value is unique';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Document has multiple elements with the same accesskey';return out;\n}}},\"non-empty-alt\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element has a non-empty alt attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has no alt attribute or the alt attribute is empty';return out;\n}}},\"aria-label\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='aria-label attribute exists and is not empty';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='aria-label attribute does not exist or is empty';return out;\n}}},\"aria-labelledby\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='aria-labelledby attribute exists and references elements that are visible to screen readers';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='aria-labelledby attribute does not exist, references elements that do not exist or references elements that are empty or not visible';return out;\n}}},\"aria-allowed-attr\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='ARIA attributes are used correctly for the defined role';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='ARIA attribute'+(it.data && it.data.length > 1 ? 's are' : ' is')+' not allowed:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;\n}}},\"aria-required-attr\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='All required ARIA attributes are present';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Required ARIA attribute'+(it.data && it.data.length > 1 ? 's' : '')+' not present:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;\n}}},\"aria-required-children\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Required ARIA children are present';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Required ARIA '+(it.data && it.data.length > 1 ? 'children' : 'child')+' role not present:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;\n}}},\"aria-required-parent\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Required ARIA parent role present';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Required ARIA parent'+(it.data && it.data.length > 1 ? 's' : '')+' role not present:';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;\n}}},\"invalidrole\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='ARIA role is valid';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Role must be one of the valid ARIA roles';return out;\n}}},\"abstractrole\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Abstract roles are not used';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Abstract roles cannot be directly used';return out;\n}}},\"aria-valid-attr-value\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='ARIA attribute values are valid';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Invalid ARIA attribute value'+(it.data && it.data.length > 1 ? 's' : '')+':';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;\n}}},\"aria-valid-attr\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='ARIA attribute name'+(it.data && it.data.length > 1 ? 's' : '')+' are valid';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Invalid ARIA attribute name'+(it.data && it.data.length > 1 ? 's' : '')+':';var arr1=it.data;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+=' '+(value);} } return out;\n}}},\"caption\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='The multimedia element has a captions track';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='The multimedia element does not have a captions track';return out;\n}}},\"exists\":{\"impact\":\"minor\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element does not exist';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element exists';return out;\n}}},\"non-empty-if-present\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element ';if(it.data){out+='has a non-empty value attribute';}else{out+='does not have a value attribute';}return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has a value attribute and the value attribute is empty';return out;\n}}},\"non-empty-value\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element has a non-empty value attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has no value attribute or the value attribute is empty';return out;\n}}},\"button-has-visible-text\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element has inner text that is visible to screen readers';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element does not have inner text that is visible to screen readers';return out;\n}}},\"role-presentation\":{\"impact\":\"moderate\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element\\'s default semantics were overriden with role=\"presentation\"';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element\\'s default semantics were not overridden with role=\"presentation\"';return out;\n}}},\"role-none\":{\"impact\":\"moderate\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element\\'s default semantics were overriden with role=\"none\"';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element\\'s default semantics were not overridden with role=\"none\"';return out;\n}}},\"duplicate-img-label\":{\"impact\":\"minor\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element does not duplicate existing text in <img> alt text';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element contains <img> element with alt text that duplicates existing text';return out;\n}}},\"focusable-no-name\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element is not in tab order or has accessible text';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element is in tab order and does not have accessible text';return out;\n}}},\"internal-link-present\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Valid skip link found';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='No valid skip link found';return out;\n}}},\"header-present\":{\"impact\":\"moderate\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Page has a header';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Page does not have a header';return out;\n}}},\"landmark\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Page has a landmark region';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Page does not have a landmark region';return out;\n}}},\"group-labelledby\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='All elements with the name \"'+(it.data.name)+'\" reference the same element with aria-labelledby';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='All elements with the name \"'+(it.data.name)+'\" do not reference the same element with aria-labelledby';return out;\n}}},\"fieldset\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element is contained in a fieldset';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='';var code = it.data && it.data.failureCode;if(code === 'no-legend'){out+='Fieldset does not have a legend as its first child';}else if(code === 'empty-legend'){out+='Legend does not have text that is visible to screen readers';}else if(code === 'mixed-inputs'){out+='Fieldset contains unrelated inputs';}else if(code === 'no-group-label'){out+='ARIA group does not have aria-label or aria-labelledby';}else if(code === 'group-mixed-inputs'){out+='ARIA group contains unrelated inputs';}else{out+='Element does not have a containing fieldset or ARIA group';}return out;\n}}},\"color-contrast\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='';if(it.data && it.data.contrastRatio){out+='Element has sufficient color contrast of '+(it.data.contrastRatio);}else{out+='Unable to determine contrast ratio';}return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has insufficient color contrast of '+(it.data.contrastRatio)+' (foreground color: '+(it.data.fgColor)+', background color: '+(it.data.bgColor)+', font size: '+(it.data.fontSize)+', font weight: '+(it.data.fontWeight)+')';return out;\n}}},\"consistent-columns\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Table has consistent column widths';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Table does not have the same number of columns in every row';return out;\n}}},\"cell-no-header\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='All data cells have table headers';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Some data cells do not have table headers';return out;\n}}},\"headers-visible-text\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Header cell has visible text';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Header cell does not have visible text';return out;\n}}},\"headers-attr-reference\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='headers attribute references elements that are visible to screen readers';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='headers attribute references element that is not visible to screen readers';return out;\n}}},\"th-scope\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='<th> elements use scope attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='<th> elements must use scope attribute';return out;\n}}},\"no-caption\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Table has a <caption>';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Table does not have a <caption>';return out;\n}}},\"th-headers-attr\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='<th> elements do not use headers attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='<th> elements should not use headers attribute';return out;\n}}},\"th-single-row-column\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='<th> elements are used when there is only a single row and single column of headers';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='<th> elements should only be used when there is a single row and single column of headers';return out;\n}}},\"same-caption-summary\":{\"impact\":\"moderate\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Content of summary attribute and <caption> are not duplicated';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Content of summary attribute and <caption> element are indentical';return out;\n}}},\"rowspan\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Table does not have cells with rowspan attribute greater than 1';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Table has cells whose rowspan attribute is not equal to 1';return out;\n}}},\"structured-dlitems\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='When not empty, element has both <dt> and <dd> elements';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='When not empty, element does not have at least one <dt> element followed by at least one <dd> element';return out;\n}}},\"only-dlitems\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element only has children that are <dt> or <dd> elements';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has children that are not <dt> or <dd> elements';return out;\n}}},\"dlitem\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Description list item has a <dl> parent element';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Description list item does not have a <dl> parent element';return out;\n}}},\"doc-has-title\":{\"impact\":\"moderate\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Document has a non-empty <title> element';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Document does not have a non-empty <title> element';return out;\n}}},\"duplicate-id\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Document has no elements that share the same id attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Document has multiple elements with the same id attribute: '+(it.data);return out;\n}}},\"has-visible-text\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element has text that is visible to screen readers';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element does not have text that is visible to screen readers';return out;\n}}},\"non-empty-title\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element has a title attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has no title attribute or the title attribute is empty';return out;\n}}},\"unique-frame-title\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element\\'s title attribute is unique';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element\\'s title attribute is not unique';return out;\n}}},\"heading-order\":{\"impact\":\"minor\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Heading order valid';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Heading order invalid';return out;\n}}},\"has-lang\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='The <html> element has a lang attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='The <html> element does not have a lang attribute';return out;\n}}},\"valid-lang\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Value of lang attribute is included in the list of valid languages';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Value of lang attribute not included in the list of valid languages';return out;\n}}},\"has-alt\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element has an alt attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element does not have an alt attribute';return out;\n}}},\"title-only\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Form element does not solely use title attribute for its label';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Only title used to generate label for form element';return out;\n}}},\"implicit-label\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Form element has an implicit (wrapped) <label>';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Form element does not have an implicit (wrapped) <label>';return out;\n}}},\"explicit-label\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Form element has an explicit <label>';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Form element does not have an explicit <label>';return out;\n}}},\"help-same-as-label\":{\"impact\":\"minor\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Help text (title or aria-describedby) does not duplicate label text';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Help text (title or aria-describedby) text is the same as the label text';return out;\n}}},\"multiple-label\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Form element does not have multiple <label> elements';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Form element has multiple <label> elements';return out;\n}}},\"has-th\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Layout table does not use <th> elements';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Layout table uses <th> elements';return out;\n}}},\"has-caption\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Layout table does not use <caption> element';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Layout table uses <caption> element';return out;\n}}},\"has-summary\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Layout table does not use summary attribute';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Layout table uses summary attribute';return out;\n}}},\"only-listitems\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='List element only has children that are <li>, <script> or <template> elements';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='List element has children that are not <li>, <script> or <template> elements';return out;\n}}},\"listitem\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='List item has a <ul>, <ol> or role=\"list\" parent element';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='List item does not have a <ul>, <ol> or role=\"list\" parent element';return out;\n}}},\"meta-refresh\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='<meta> tag does not immediately refresh the page';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='<meta> tag forces timed refresh of page';return out;\n}}},\"meta-viewport\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='<meta> tag does not disable zooming';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='<meta> tag disables zooming';return out;\n}}},\"region\":{\"impact\":\"moderate\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Content contained by ARIA landmark';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Content not contained by an ARIA landmark';return out;\n}}},\"html5-scope\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Scope attribute is only used on table header elements (<th>)';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='In HTML 5, scope attributes may only be used on table header elements (<th>)';return out;\n}}},\"html4-scope\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Scope attribute is only used on table cell elements (<th> and <td>)';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='In HTML 4, the scope attribute may only be used on table cell elements (<th> and <td>)';return out;\n}}},\"scope-value\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Scope attribute is used correctly';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='The value of the scope attribute may only be \\'row\\' or \\'col\\'';return out;\n}}},\"skip-link\":{\"impact\":\"critical\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Valid skip link found';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='No valid skip link found';return out;\n}}},\"tabindex\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='Element does not have a tabindex greater than 0';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='Element has a tabindex greater than 0';return out;\n}}},\"description\":{\"impact\":\"serious\",\"messages\":{\"pass\":function anonymous(it\n/**/) {\nvar out='The multimedia element has an audio description track';return out;\n},\"fail\":function anonymous(it\n/**/) {\nvar out='The multimedia element does not have an audio description track';return out;\n}}}},\"failureSummaries\":{\"any\":{\"failureMessage\":function anonymous(it\n/**/) {\nvar out='Fix any of the following:';var arr1=it;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+='\\n  '+(value.split('\\n').join('\\n  '));} } return out;\n}},\"none\":{\"failureMessage\":function anonymous(it\n/**/) {\nvar out='Fix all of the following:';var arr1=it;if(arr1){var value,i1=-1,l1=arr1.length-1;while(i1<l1){value=arr1[i1+=1];out+='\\n  '+(value.split('\\n').join('\\n  '));} } return out;\n}}}},\"rules\":[{\"id\":\"accesskeys\",\"selector\":\"[accesskey]\",\"tags\":[\"wcag2a\",\"wcag211\"],\"all\":[],\"any\":[],\"none\":[\"accesskeys\"]},{\"id\":\"area-alt\",\"selector\":\"map area[href]\",\"excludeHidden\":false,\"tags\":[\"wcag2a\",\"wcag111\",\"section508\",\"section508a\"],\"all\":[],\"any\":[\"non-empty-alt\",\"aria-label\",\"aria-labelledby\"],\"none\":[]},{\"id\":\"aria-allowed-attr\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[\"aria-allowed-attr\"],\"none\":[]},{\"id\":\"aria-required-attr\",\"selector\":\"[role]\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[\"aria-required-attr\"],\"none\":[]},{\"id\":\"aria-required-children\",\"selector\":\"[role]\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[\"aria-required-children\"],\"none\":[]},{\"id\":\"aria-required-parent\",\"selector\":\"[role]\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[\"aria-required-parent\"],\"none\":[]},{\"id\":\"aria-roles\",\"selector\":\"[role]\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[],\"none\":[\"invalidrole\",\"abstractrole\"]},{\"id\":\"aria-valid-attr-value\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[{\"options\":[],\"id\":\"aria-valid-attr-value\"}],\"none\":[]},{\"id\":\"aria-valid-attr\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[{\"options\":[],\"id\":\"aria-valid-attr\"}],\"none\":[]},{\"id\":\"audio-caption\",\"selector\":\"audio\",\"excludeHidden\":false,\"tags\":[\"wcag2a\",\"wcag122\",\"section508\",\"section508a\"],\"all\":[],\"any\":[],\"none\":[\"caption\"]},{\"id\":\"blink\",\"selector\":\"blink\",\"tags\":[\"wcag2a\",\"wcag222\"],\"all\":[],\"any\":[],\"none\":[\"exists\"]},{\"id\":\"button-name\",\"selector\":\"button, [role=\\\"button\\\"], input[type=\\\"button\\\"], input[type=\\\"submit\\\"], input[type=\\\"reset\\\"]\",\"tags\":[\"wcag2a\",\"wcag412\",\"section508\",\"section508a\"],\"all\":[],\"any\":[\"non-empty-if-present\",\"non-empty-value\",\"button-has-visible-text\",\"aria-label\",\"aria-labelledby\",\"role-presentation\",\"role-none\"],\"none\":[\"duplicate-img-label\",\"focusable-no-name\"]},{\"id\":\"bypass\",\"selector\":\"html\",\"pageLevel\":true,\"matches\":function (node) {\nreturn !!node.querySelector('a[href]');\n\n},\"tags\":[\"wcag2a\",\"wcag241\",\"section508\",\"section508o\"],\"all\":[],\"any\":[\"internal-link-present\",\"header-present\",\"landmark\"],\"none\":[]},{\"id\":\"checkboxgroup\",\"selector\":\"input[type=checkbox][name]\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[\"group-labelledby\",\"fieldset\"],\"none\":[]},{\"id\":\"color-contrast\",\"options\":{\"noScroll\":false},\"selector\":\"*\",\"tags\":[\"wcag2aa\",\"wcag143\"],\"all\":[],\"any\":[\"color-contrast\"],\"none\":[]},{\"id\":\"data-table\",\"selector\":\"table\",\"matches\":function (node) {\nreturn commons.table.isDataTable(node);\n},\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[\"consistent-columns\"],\"none\":[\"cell-no-header\",\"headers-visible-text\",\"headers-attr-reference\",\"th-scope\",\"no-caption\",\"th-headers-attr\",\"th-single-row-column\",\"same-caption-summary\",\"rowspan\"]},{\"id\":\"definition-list\",\"selector\":\"dl:not([role])\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[],\"none\":[\"structured-dlitems\",\"only-dlitems\"]},{\"id\":\"dlitem\",\"selector\":\"dd:not([role]), dt:not([role])\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[\"dlitem\"],\"none\":[]},{\"id\":\"document-title\",\"selector\":\"html\",\"tags\":[\"wcag2a\",\"wcag242\"],\"all\":[],\"any\":[\"doc-has-title\"],\"none\":[]},{\"id\":\"duplicate-id\",\"selector\":\"[id]\",\"tags\":[\"wcag2a\",\"wcag411\"],\"all\":[],\"any\":[\"duplicate-id\"],\"none\":[]},{\"id\":\"empty-heading\",\"selector\":\"h1, h2, h3, h4, h5, h6, [role=\\\"heading\\\"]\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[\"has-visible-text\",\"role-presentation\",\"role-none\"],\"none\":[]},{\"id\":\"frame-title\",\"selector\":\"frame, iframe\",\"tags\":[\"wcag2a\",\"wcag241\"],\"all\":[],\"any\":[\"non-empty-title\"],\"none\":[\"unique-frame-title\"]},{\"id\":\"heading-order\",\"selector\":\"h1,h2,h3,h4,h5,h6,[role=heading]\",\"enabled\":false,\"tags\":[\"best-practice\"],\"all\":[],\"any\":[\"heading-order\"],\"none\":[]},{\"id\":\"html-lang\",\"selector\":\"html\",\"tags\":[\"wcag2a\",\"wcag311\"],\"all\":[],\"any\":[\"has-lang\"],\"none\":[{\"options\":[\"aa\",\"ab\",\"ae\",\"af\",\"ak\",\"am\",\"an\",\"ar\",\"as\",\"av\",\"ay\",\"az\",\"ba\",\"be\",\"bg\",\"bh\",\"bi\",\"bm\",\"bn\",\"bo\",\"br\",\"bs\",\"ca\",\"ce\",\"ch\",\"co\",\"cr\",\"cs\",\"cu\",\"cv\",\"cy\",\"da\",\"de\",\"dv\",\"dz\",\"ee\",\"el\",\"en\",\"eo\",\"es\",\"et\",\"eu\",\"fa\",\"ff\",\"fi\",\"fj\",\"fo\",\"fr\",\"fy\",\"ga\",\"gd\",\"gl\",\"gn\",\"gu\",\"gv\",\"ha\",\"he\",\"hi\",\"ho\",\"hr\",\"ht\",\"hu\",\"hy\",\"hz\",\"ia\",\"id\",\"ie\",\"ig\",\"ii\",\"ik\",\"in\",\"io\",\"is\",\"it\",\"iu\",\"iw\",\"ja\",\"ji\",\"jv\",\"jw\",\"ka\",\"kg\",\"ki\",\"kj\",\"kk\",\"kl\",\"km\",\"kn\",\"ko\",\"kr\",\"ks\",\"ku\",\"kv\",\"kw\",\"ky\",\"la\",\"lb\",\"lg\",\"li\",\"ln\",\"lo\",\"lt\",\"lu\",\"lv\",\"mg\",\"mh\",\"mi\",\"mk\",\"ml\",\"mn\",\"mo\",\"mr\",\"ms\",\"mt\",\"my\",\"na\",\"nb\",\"nd\",\"ne\",\"ng\",\"nl\",\"nn\",\"no\",\"nr\",\"nv\",\"ny\",\"oc\",\"oj\",\"om\",\"or\",\"os\",\"pa\",\"pi\",\"pl\",\"ps\",\"pt\",\"qu\",\"rm\",\"rn\",\"ro\",\"ru\",\"rw\",\"sa\",\"sc\",\"sd\",\"se\",\"sg\",\"sh\",\"si\",\"sk\",\"sl\",\"sm\",\"sn\",\"so\",\"sq\",\"sr\",\"ss\",\"st\",\"su\",\"sv\",\"sw\",\"ta\",\"te\",\"tg\",\"th\",\"ti\",\"tk\",\"tl\",\"tn\",\"to\",\"tr\",\"ts\",\"tt\",\"tw\",\"ty\",\"ug\",\"uk\",\"ur\",\"uz\",\"ve\",\"vi\",\"vo\",\"wa\",\"wo\",\"xh\",\"yi\",\"yo\",\"za\",\"zh\",\"zu\"],\"id\":\"valid-lang\"}]},{\"id\":\"image-alt\",\"selector\":\"img\",\"tags\":[\"wcag2a\",\"wcag111\",\"section508\",\"section508a\"],\"all\":[],\"any\":[\"has-alt\",\"aria-label\",\"aria-labelledby\",\"non-empty-title\",\"role-presentation\",\"role-none\"],\"none\":[]},{\"id\":\"input-image-alt\",\"selector\":\"input[type=\\\"image\\\"]\",\"tags\":[\"wcag2a\",\"wcag111\",\"section508\",\"section508a\"],\"all\":[],\"any\":[\"non-empty-alt\",\"aria-label\",\"aria-labelledby\"],\"none\":[]},{\"id\":\"label-title-only\",\"selector\":\"input:not([type='hidden']):not([type='image']):not([type='button']):not([type='submit']):not([type='reset']), select, textarea\",\"enabled\":false,\"tags\":[\"best-practice\"],\"all\":[],\"any\":[],\"none\":[\"title-only\"]},{\"id\":\"label\",\"selector\":\"input:not([type='hidden']):not([type='image']):not([type='button']):not([type='submit']):not([type='reset']), select, textarea\",\"tags\":[\"wcag2a\",\"wcag332\",\"wcag131\",\"section508\",\"section508n\"],\"all\":[],\"any\":[\"aria-label\",\"aria-labelledby\",\"implicit-label\",\"explicit-label\",\"non-empty-title\"],\"none\":[\"help-same-as-label\",\"multiple-label\"]},{\"id\":\"layout-table\",\"selector\":\"table\",\"matches\":function (node) {\nreturn !commons.table.isDataTable(node);\n},\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[],\"none\":[\"has-th\",\"has-caption\",\"has-summary\"]},{\"id\":\"link-name\",\"selector\":\"a[href]:not([role=\\\"button\\\"]), [role=link][href]\",\"tags\":[\"wcag2a\",\"wcag111\",\"wcag412\",\"section508\",\"section508a\"],\"all\":[],\"any\":[\"has-visible-text\",\"aria-label\",\"aria-labelledby\",\"role-presentation\",\"role-none\"],\"none\":[\"duplicate-img-label\",\"focusable-no-name\"]},{\"id\":\"list\",\"selector\":\"ul:not([role]), ol:not([role])\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[],\"none\":[\"only-listitems\"]},{\"id\":\"listitem\",\"selector\":\"li:not([role])\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[\"listitem\"],\"none\":[]},{\"id\":\"marquee\",\"selector\":\"marquee\",\"tags\":[\"wcag2a\",\"wcag222\",\"section508\",\"section508j\"],\"all\":[],\"any\":[],\"none\":[\"exists\"]},{\"id\":\"meta-refresh\",\"selector\":\"meta[http-equiv=\\\"refresh\\\"]\",\"excludeHidden\":false,\"tags\":[\"wcag2a\",\"wcag2aaa\",\"wcag221\",\"wcag224\",\"wcag325\"],\"all\":[],\"any\":[\"meta-refresh\"],\"none\":[]},{\"id\":\"meta-viewport\",\"selector\":\"meta[name=\\\"viewport\\\"]\",\"excludeHidden\":false,\"tags\":[\"wcag2aa\",\"wcag144\"],\"all\":[],\"any\":[\"meta-viewport\"],\"none\":[]},{\"id\":\"object-alt\",\"selector\":\"object\",\"tags\":[\"wcag2a\",\"wcag111\"],\"all\":[],\"any\":[\"has-visible-text\"],\"none\":[]},{\"id\":\"radiogroup\",\"selector\":\"input[type=radio][name]\",\"tags\":[\"wcag2a\",\"wcag131\"],\"all\":[],\"any\":[\"group-labelledby\",\"fieldset\"],\"none\":[]},{\"id\":\"region\",\"selector\":\"html\",\"pageLevel\":true,\"enabled\":false,\"tags\":[\"best-practice\"],\"all\":[],\"any\":[\"region\"],\"none\":[]},{\"id\":\"scope\",\"selector\":\"[scope]\",\"enabled\":false,\"tags\":[\"best-practice\"],\"all\":[],\"any\":[\"html5-scope\",\"html4-scope\"],\"none\":[\"scope-value\"]},{\"id\":\"server-side-image-map\",\"selector\":\"img[ismap]\",\"tags\":[\"wcag2a\",\"wcag211\",\"section508\",\"section508f\"],\"all\":[],\"any\":[],\"none\":[\"exists\"]},{\"id\":\"skip-link\",\"selector\":\"a[href]\",\"pageLevel\":true,\"enabled\":false,\"tags\":[\"best-practice\"],\"all\":[],\"any\":[\"skip-link\"],\"none\":[]},{\"id\":\"tabindex\",\"selector\":\"[tabindex]\",\"tags\":[\"best-practice\"],\"all\":[],\"any\":[\"tabindex\"],\"none\":[]},{\"id\":\"valid-lang\",\"selector\":\"[lang]:not(html), [xml\\\\:lang]:not(html)\",\"tags\":[\"wcag2aa\",\"wcag312\"],\"all\":[],\"any\":[],\"none\":[{\"options\":[\"aa\",\"ab\",\"ae\",\"af\",\"ak\",\"am\",\"an\",\"ar\",\"as\",\"av\",\"ay\",\"az\",\"ba\",\"be\",\"bg\",\"bh\",\"bi\",\"bm\",\"bn\",\"bo\",\"br\",\"bs\",\"ca\",\"ce\",\"ch\",\"co\",\"cr\",\"cs\",\"cu\",\"cv\",\"cy\",\"da\",\"de\",\"dv\",\"dz\",\"ee\",\"el\",\"en\",\"eo\",\"es\",\"et\",\"eu\",\"fa\",\"ff\",\"fi\",\"fj\",\"fo\",\"fr\",\"fy\",\"ga\",\"gd\",\"gl\",\"gn\",\"gu\",\"gv\",\"ha\",\"he\",\"hi\",\"ho\",\"hr\",\"ht\",\"hu\",\"hy\",\"hz\",\"ia\",\"id\",\"ie\",\"ig\",\"ii\",\"ik\",\"in\",\"io\",\"is\",\"it\",\"iu\",\"iw\",\"ja\",\"ji\",\"jv\",\"jw\",\"ka\",\"kg\",\"ki\",\"kj\",\"kk\",\"kl\",\"km\",\"kn\",\"ko\",\"kr\",\"ks\",\"ku\",\"kv\",\"kw\",\"ky\",\"la\",\"lb\",\"lg\",\"li\",\"ln\",\"lo\",\"lt\",\"lu\",\"lv\",\"mg\",\"mh\",\"mi\",\"mk\",\"ml\",\"mn\",\"mo\",\"mr\",\"ms\",\"mt\",\"my\",\"na\",\"nb\",\"nd\",\"ne\",\"ng\",\"nl\",\"nn\",\"no\",\"nr\",\"nv\",\"ny\",\"oc\",\"oj\",\"om\",\"or\",\"os\",\"pa\",\"pi\",\"pl\",\"ps\",\"pt\",\"qu\",\"rm\",\"rn\",\"ro\",\"ru\",\"rw\",\"sa\",\"sc\",\"sd\",\"se\",\"sg\",\"sh\",\"si\",\"sk\",\"sl\",\"sm\",\"sn\",\"so\",\"sq\",\"sr\",\"ss\",\"st\",\"su\",\"sv\",\"sw\",\"ta\",\"te\",\"tg\",\"th\",\"ti\",\"tk\",\"tl\",\"tn\",\"to\",\"tr\",\"ts\",\"tt\",\"tw\",\"ty\",\"ug\",\"uk\",\"ur\",\"uz\",\"ve\",\"vi\",\"vo\",\"wa\",\"wo\",\"xh\",\"yi\",\"yo\",\"za\",\"zh\",\"zu\"],\"id\":\"valid-lang\"}]},{\"id\":\"video-caption\",\"selector\":\"video\",\"tags\":[\"wcag2a\",\"wcag122\",\"wcag123\",\"section508\",\"section508a\"],\"all\":[],\"any\":[],\"none\":[\"caption\"]},{\"id\":\"video-description\",\"selector\":\"video\",\"tags\":[\"wcag2aa\",\"wcag125\",\"section508\",\"section508a\"],\"all\":[],\"any\":[],\"none\":[\"description\"]}],\"checks\":[{\"id\":\"abstractrole\",\"evaluate\":function (node, options) {\nreturn commons.aria.getRoleType(node.getAttribute('role')) === 'abstract';\n\n}},{\"id\":\"aria-allowed-attr\",\"matches\":function (node) {\n\nvar role = node.getAttribute('role');\nif (!role) {\n\trole = commons.aria.implicitRole(node);\n}\nvar allowed = commons.aria.allowedAttr(role);\nif (role && allowed) {\n\tvar aria = /^aria-/;\n\tif (node.hasAttributes()) {\n\t\tvar attrs = node.attributes;\n\t\tfor (var i = 0, l = attrs.length; i < l; i++) {\n\t\t\tif (aria.test(attrs[i].nodeName)) {\n\t\t\t\treturn true;\n\t\t\t}\n\t\t}\n\t}\n}\n\nreturn false;\n},\"evaluate\":function (node, options) {\nvar invalid = [];\n\nvar attr, attrName, allowed,\n\trole = node.getAttribute('role'),\n\tattrs = node.attributes;\n\nif (!role) {\n\trole = commons.aria.implicitRole(node);\n}\nallowed = commons.aria.allowedAttr(role);\nif (role && allowed) {\n\tfor (var i = 0, l = attrs.length; i < l; i++) {\n\t\tattr = attrs[i];\n\t\tattrName = attr.nodeName;\n\t\tif (commons.aria.validateAttr(attrName) && allowed.indexOf(attrName) === -1) {\n\t\t\tinvalid.push(attrName + '=\"' + attr.nodeValue + '\"');\n\t\t}\n\t}\n}\n\nif (invalid.length) {\n\tthis.data(invalid);\n\treturn false;\n}\n\nreturn true;\n}},{\"id\":\"invalidrole\",\"evaluate\":function (node, options) {\nreturn !commons.aria.isValidRole(node.getAttribute('role'));\n\n\n\n}},{\"id\":\"aria-required-attr\",\"evaluate\":function (node, options) {\nvar missing = [];\n\nif (node.hasAttributes()) {\n\tvar attr,\n\t\trole = node.getAttribute('role'),\n\t\trequired = commons.aria.requiredAttr(role);\n\n\tif (role && required) {\n\t\tfor (var i = 0, l = required.length; i < l; i++) {\n\t\t\tattr = required[i];\n\t\t\tif (!node.getAttribute(attr)) {\n\t\t\t\tmissing.push(attr);\n\t\t\t}\n\t\t}\n\t}\n}\n\nif (missing.length) {\n\tthis.data(missing);\n\treturn false;\n}\n\nreturn true;\n}},{\"id\":\"aria-required-children\",\"evaluate\":function (node, options) {\nvar requiredOwned = commons.aria.requiredOwned,\nimplicitNodes = commons.aria.implicitNodes,\nmatchesSelector = commons.utils.matchesSelector,\nidrefs = commons.dom.idrefs;\n\nfunction owns(node, role, ariaOwned) {\n\tif (node === null) { return false; }\n\tvar implicit = implicitNodes(role),\n\tselector = ['[role=\"' + role + '\"]'];\n\n\tif (implicit) {\n\t\tselector = selector.concat(implicit);\n\t}\n\n\tselector = selector.join(',');\n\n\treturn ariaOwned ? (matchesSelector(node, selector) || !!node.querySelector(selector)) :\n\t\t!!node.querySelector(selector);\n}\n\nfunction ariaOwns(nodes, role) {\n\tvar index, length;\n\n\tfor (index = 0, length = nodes.length; index < length; index++) {\n\t\tif (nodes[index] === null) { continue; }\n\t\tif (owns(nodes[index], role, true)) {\n\t\t\treturn true;\n\t\t}\n\t}\n\treturn false;\n}\n\nfunction missingRequiredChildren(node, childRoles, all) {\n\n\tvar i,\n\tl = childRoles.length,\n\tmissing = [],\n\townedElements = idrefs(node, 'aria-owns');\n\n\tfor (i = 0; i < l; i++) {\n\t\tvar r = childRoles[i];\n\t\tif (owns(node, r) || ariaOwns(ownedElements, r)) {\n\t\t\tif (!all) { return null; }\n\t\t} else {\n\t\t\tif (all) { missing.push(r); }\n\t\t}\n\t}\n\n\tif (missing.length) { return missing; }\n\tif (!all && childRoles.length) { return childRoles; }\n\treturn null;\n}\n\nvar role = node.getAttribute('role');\nvar required = requiredOwned(role);\n\nif (!required) { return true; }\n\nvar all = false;\nvar childRoles = required.one;\nif (!childRoles) {\n\tvar all = true;\n\tchildRoles = required.all;\n}\n\nvar missing = missingRequiredChildren(node, childRoles, all);\n\nif (!missing) { return true; }\n\nthis.data(missing);\nreturn false;\n\n}},{\"id\":\"aria-required-parent\",\"evaluate\":function (node, options) {\nfunction getSelector(role) {\n\tvar impliedNative = commons.aria.implicitNodes(role) || [];\n\treturn impliedNative.concat('[role=\"' + role + '\"]').join(',');\n}\n\nfunction getMissingContext(element, requiredContext, includeElement) {\n\tvar index, length,\n\trole = element.getAttribute('role'),\n\tmissing = [];\n\n\tif (!requiredContext) {\n\t\trequiredContext = commons.aria.requiredContext(role);\n\t}\n\n\tif (!requiredContext) { return null; }\n\n\tfor (index = 0, length = requiredContext.length; index < length; index++) {\n\t\tif (includeElement && commons.utils.matchesSelector(element, getSelector(requiredContext[index]))) {\n\t\t\treturn null;\n\t\t}\n\t\tif (commons.dom.findUp(element, getSelector(requiredContext[index]))) {\n\t\t\t//if one matches, it passes\n\t\t\treturn null;\n\t\t} else {\n\t\t\tmissing.push(requiredContext[index]);\n\t\t}\n\t}\n\n\treturn missing;\n}\n\nfunction getAriaOwners(element) {\n\tvar owners = [],\n\t\to = null;\n\n\twhile (element) {\n\t\tif (element.id) {\n\t\t\to = document.querySelector('[aria-owns~=' + commons.utils.escapeSelector(element.id) + ']');\n\t\t\tif (o) { owners.push(o); }\n\t\t}\n\t\telement = element.parentNode;\n\t}\n\n\treturn owners.length ? owners : null;\n}\n\nvar missingParents = getMissingContext(node);\n\nif (!missingParents) { return true; }\n\nvar owners = getAriaOwners(node);\n\nif (owners) {\n\tfor (var i = 0, l = owners.length; i < l; i++) {\n\t\tmissingParents = getMissingContext(owners[i], missingParents, true);\n\t\tif (!missingParents) { return true; }\n\t}\n}\n\nthis.data(missingParents);\nreturn false;\n\n}},{\"id\":\"aria-valid-attr-value\",\"matches\":function (node) {\nvar aria = /^aria-/;\nif (node.hasAttributes()) {\n\tvar attrs = node.attributes;\n\tfor (var i = 0, l = attrs.length; i < l; i++) {\n\t\tif (aria.test(attrs[i].nodeName)) {\n\t\t\treturn true;\n\t\t}\n\t}\n}\n\nreturn false;\n},\"evaluate\":function (node, options) {\noptions = Array.isArray(options) ? options : [];\n\nvar invalid = [],\n\taria = /^aria-/;\n\nvar attr, attrName,\n\tattrs = node.attributes;\n\nfor (var i = 0, l = attrs.length; i < l; i++) {\n\tattr = attrs[i];\n\tattrName = attr.nodeName;\n\tif (options.indexOf(attrName) === -1 && aria.test(attrName) &&\n\t\t!commons.aria.validateAttrValue(node, attrName)) {\n\n\t\tinvalid.push(attrName + '=\"' + attr.nodeValue + '\"');\n\t}\n}\n\nif (invalid.length) {\n\tthis.data(invalid);\n\treturn false;\n}\n\nreturn true;\n\n},\"options\":[]},{\"id\":\"aria-valid-attr\",\"matches\":function (node) {\nvar aria = /^aria-/;\nif (node.hasAttributes()) {\n\tvar attrs = node.attributes;\n\tfor (var i = 0, l = attrs.length; i < l; i++) {\n\t\tif (aria.test(attrs[i].nodeName)) {\n\t\t\treturn true;\n\t\t}\n\t}\n}\n\nreturn false;\n},\"evaluate\":function (node, options) {\noptions = Array.isArray(options) ? options : [];\n\nvar invalid = [],\n\taria = /^aria-/;\n\nvar attr,\n\tattrs = node.attributes;\n\nfor (var i = 0, l = attrs.length; i < l; i++) {\n\tattr = attrs[i].nodeName;\n\tif (options.indexOf(attr) === -1 && aria.test(attr) && !commons.aria.validateAttr(attr)) {\n\t\tinvalid.push(attr);\n\t}\n}\n\nif (invalid.length) {\n\tthis.data(invalid);\n\treturn false;\n}\n\nreturn true;\n\n},\"options\":[]},{\"id\":\"color-contrast\",\"matches\":function (node) {\nvar nodeName = node.nodeName.toUpperCase(),\n\tnodeType = node.type,\n\tdoc = document;\n\nif (nodeName === 'INPUT') {\n\treturn ['hidden', 'range', 'color', 'checkbox', 'radio', 'image'].indexOf(nodeType) === -1 && !node.disabled;\n}\n\nif (nodeName === 'SELECT') {\n\treturn !!node.options.length && !node.disabled;\n}\n\nif (nodeName === 'TEXTAREA') {\n\treturn !node.disabled;\n}\n\nif (nodeName === 'OPTION') {\n\treturn false;\n}\n\nif (nodeName === 'BUTTON' && node.disabled) {\n\treturn false;\n}\n\n// check if the element is a label for a disabled control\nif (nodeName === 'LABEL') {\n\t// explicit label of disabled input\n\tvar candidate = node.htmlFor && doc.getElementById(node.htmlFor);\n\tif (candidate && candidate.disabled) {\n\t\treturn false;\n\t}\n\n\tvar candidate = node.querySelector('input:not([type=\"hidden\"]):not([type=\"image\"])' +\n\t\t':not([type=\"button\"]):not([type=\"submit\"]):not([type=\"reset\"]), select, textarea');\n\tif (candidate && candidate.disabled) {\n\t\treturn false;\n\t}\n\n}\n\n// label of disabled control associated w/ aria-labelledby\nif (node.id) {\n\tvar candidate = doc.querySelector('[aria-labelledby~=' + commons.utils.escapeSelector(node.id) + ']');\n\tif (candidate && candidate.disabled) {\n\t\treturn false;\n\t}\n}\n\nif (commons.text.visible(node, false, true) === '') {\n\treturn false;\n}\n\nvar range = document.createRange(),\n\tchildNodes = node.childNodes,\n\tlength = childNodes.length,\n\tchild, index;\n\nfor (index = 0; index < length; index++) {\n\tchild = childNodes[index];\n\n\tif (child.nodeType === 3 && commons.text.sanitize(child.nodeValue) !== '') {\n\t\trange.selectNodeContents(child);\n\t}\n}\n\nvar rects = range.getClientRects();\nlength = rects.length;\n\nfor (index = 0; index < length; index++) {\n\t//check to see if the rectangle impinges\n\tif (commons.dom.visuallyOverlaps(rects[index], node)) {\n\t\treturn true;\n\t}\n}\n\nreturn false;\n\n},\"evaluate\":function (node, options) {\nvar useScroll = !(options || {}).noScroll;\nvar bgNodes = [],\n\tbgColor = commons.color.getBackgroundColor(node, bgNodes, useScroll),\n\tfgColor = commons.color.getForegroundColor(node, useScroll);\n\n//We don't know, so we'll pass it provisionally\nif (fgColor === null || bgColor === null) {\n\treturn true;\n}\n\nvar nodeStyle = window.getComputedStyle(node);\nvar fontSize = parseFloat(nodeStyle.getPropertyValue('font-size'));\nvar fontWeight = nodeStyle.getPropertyValue('font-weight');\nvar bold = (['bold', 'bolder', '600', '700', '800', '900'].indexOf(fontWeight) !== -1);\n\nvar cr = commons.color.hasValidContrastRatio(bgColor, fgColor, fontSize, bold);\n\nthis.data({\n\tfgColor: fgColor.toHexString(),\n\tbgColor: bgColor.toHexString(),\n\tcontrastRatio: cr.contrastRatio.toFixed(2),\n\tfontSize: (fontSize * 72 / 96).toFixed(1) + 'pt',\n\tfontWeight: bold ? 'bold' : 'normal',\n});\n\nif (!cr.isValid) {\n\tthis.relatedNodes(bgNodes);\n}\nreturn cr.isValid;\n\n}},{\"id\":\"fieldset\",\"evaluate\":function (node, options) {\nvar failureCode,\n\tself = this;\n\n\nfunction getUnrelatedElements(parent, name) {\n\treturn commons.utils.toArray(parent.querySelectorAll('select,textarea,button,input:not([name=\"' + name +\n\t\t'\"]):not([type=\"hidden\"])'));\n}\n\nfunction checkFieldset(group, name) {\n\n\tvar firstNode = group.firstElementChild;\n\tif (!firstNode || firstNode.nodeName.toUpperCase() !== 'LEGEND') {\n\t\tself.relatedNodes([group]);\n\t\tfailureCode = 'no-legend';\n\t\treturn false;\n\t}\n\tif (!commons.text.accessibleText(firstNode)) {\n\t\tself.relatedNodes([firstNode]);\n\t\tfailureCode = 'empty-legend';\n\t\treturn false;\n\t}\n\tvar otherElements = getUnrelatedElements(group, name);\n\tif (otherElements.length) {\n\t\tself.relatedNodes(otherElements);\n\t\tfailureCode = 'mixed-inputs';\n\t\treturn false;\n\t}\n\treturn true;\n}\n\nfunction checkARIAGroup(group, name) {\n\n\tvar hasLabelledByText = commons.dom.idrefs(group, 'aria-labelledby').some(function (element) {\n\t\treturn element && commons.text.accessibleText(element);\n\t});\n\tvar ariaLabel = group.getAttribute('aria-label');\n\tif (!hasLabelledByText && !(ariaLabel && commons.text.sanitize(ariaLabel))) {\n\t\tself.relatedNodes(group);\n\t\tfailureCode = 'no-group-label';\n\t\treturn false;\n\t}\n\n\tvar otherElements = getUnrelatedElements(group, name);\n\tif (otherElements.length) {\n\t\tself.relatedNodes(otherElements);\n\t\tfailureCode = 'group-mixed-inputs';\n\t\treturn false;\n\t}\n\treturn true;\n}\n\nfunction spliceCurrentNode(nodes, current) {\n\treturn commons.utils.toArray(nodes).filter(function (candidate) {\n\t\treturn candidate !== current;\n\t});\n}\n\nfunction runCheck(element) {\n\tvar name = commons.utils.escapeSelector(node.name);\n\tvar matchingNodes = document.querySelectorAll('input[type=\"' +\n\t\tcommons.utils.escapeSelector(node.type) + '\"][name=\"' + name + '\"]');\n\tif (matchingNodes.length < 2) {\n\t\treturn true;\n\t}\n\tvar fieldset = commons.dom.findUp(element, 'fieldset');\n\tvar group = commons.dom.findUp(element, '[role=\"group\"]' + (node.type === 'radio' ? ',[role=\"radiogroup\"]' : ''));\n\tif (!group && !fieldset) {\n\t\tfailureCode = 'no-group';\n\t\tself.relatedNodes(spliceCurrentNode(matchingNodes, element));\n\t\treturn false;\n\t}\n\treturn fieldset ? checkFieldset(fieldset, name) : checkARIAGroup(group, name);\n\n}\n\nvar data = {\n\tname: node.getAttribute('name'),\n\ttype: node.getAttribute('type')\n};\n\nvar result = runCheck(node);\nif (!result) {\n\tdata.failureCode = failureCode;\n}\nthis.data(data);\n\nreturn result;\n\n},\"after\":function (results, options) {\nvar seen = {};\n\nreturn results.filter(function (result) {\n\t// passes can pass through\n\tif (result.result) {\n\t\treturn true;\n\t}\n\tvar data = result.data;\n\tif (data) {\n\t\tseen[data.type] = seen[data.type] || {};\n\t\tif (!seen[data.type][data.name]) {\n\t\t\tseen[data.type][data.name] = [data];\n\t\t\treturn true;\n\t\t}\n\t\tvar hasBeenSeen = seen[data.type][data.name].some(function (candidate) {\n\t\t\treturn candidate.failureCode === data.failureCode;\n\t\t});\n\t\tif (!hasBeenSeen) {\n\t\t\tseen[data.type][data.name].push(data);\n\t\t}\n\n\t\treturn !hasBeenSeen;\n\n\t}\n\treturn false;\n});\n\n}},{\"id\":\"group-labelledby\",\"evaluate\":function (node, options) {\nthis.data({\n\tname: node.getAttribute('name'),\n\ttype: node.getAttribute('type')\n});\n\nvar matchingNodes = document.querySelectorAll('input[type=\"' +\n\tcommons.utils.escapeSelector(node.type) + '\"][name=\"' + commons.utils.escapeSelector(node.name) + '\"]');\nif (matchingNodes.length <= 1) {\n\treturn true;\n}\n\n// Check to see if there's an aria-labelledby value that all nodes have in common\nreturn [].map.call(matchingNodes, function (m) {\n\tvar l = m.getAttribute('aria-labelledby');\n\treturn l ? l.split(/\\s+/) : [];\n}).reduce(function (prev, curr) {\n\treturn prev.filter(function (n) {\n\t\treturn curr.indexOf(n) !== -1;\n\t});\n}).filter(function (n) {\n\tvar labelNode = document.getElementById(n);\n\treturn labelNode && commons.text.accessibleText(labelNode);\n}).length !== 0;\n\n},\"after\":function (results, options) {\nvar seen = {};\n\nreturn results.filter(function (result) {\n\tvar data = result.data;\n\tif (data) {\n\t\tseen[data.type] = seen[data.type] || {};\n\t\tif (!seen[data.type][data.name]) {\n\t\t\tseen[data.type][data.name] = true;\n\t\t\treturn true;\n\t\t}\n\t}\n\treturn false;\n});\n}},{\"id\":\"accesskeys\",\"evaluate\":function (node, options) {\nthis.data(node.getAttribute('accesskey'));\nthis.relatedNodes([node]);\nreturn true;\n\n},\"after\":function (results, options) {\nvar seen = {};\nreturn results.filter(function (r) {\n  if (!seen[r.data]) {\n    seen[r.data] = r;\n    r.relatedNodes = [];\n    return true;\n  }\n  seen[r.data].relatedNodes.push(r.relatedNodes[0]);\n  return false;\n}).map(function (r) {\n  r.result = !!r.relatedNodes.length;\n  return r;\n});\n\n}},{\"id\":\"focusable-no-name\",\"evaluate\":function (node, options) {\nvar tabIndex = node.getAttribute('tabindex'),\n\tisFocusable = commons.dom.isFocusable(node) && tabIndex > -1;\nif (!isFocusable) {\n\treturn false;\n}\nreturn !commons.text.accessibleText(node);\n\n}},{\"id\":\"tabindex\",\"evaluate\":function (node, options) {\nreturn node.tabIndex <= 0;\n\n\n}},{\"id\":\"duplicate-img-label\",\"evaluate\":function (node, options) {\nvar imgs = node.querySelectorAll('img');\nvar text = commons.text.visible(node, true);\n\nfor (var i = 0, len = imgs.length; i < len; i++) {\n\tvar imgAlt = commons.text.accessibleText(imgs[i]);\n\tif (imgAlt === text && text !== '') { return true; }\n}\n\nreturn false;\n\n},\"enabled\":false},{\"id\":\"explicit-label\",\"evaluate\":function (node, options) {\n\nvar label = document.querySelector('label[for=\"' + commons.utils.escapeSelector(node.id) + '\"]');\nif (label) {\n\treturn !!commons.text.accessibleText(label);\n}\nreturn false;\n\n},\"selector\":\"[id]\"},{\"id\":\"help-same-as-label\",\"evaluate\":function (node, options) {\n\nvar labelText = commons.text.label(node),\n\tcheck = node.getAttribute('title');\n\nif (!labelText) {\n\treturn false;\n}\n\nif (!check) {\n\tcheck = '';\n\n\tif (node.getAttribute('aria-describedby')) {\n\t\tvar ref = commons.dom.idrefs(node, 'aria-describedby');\n\t\tcheck = ref.map(function (thing) {\n\t\t\treturn thing ? commons.text.accessibleText(thing) : '';\n\t\t}).join('');\n\t}\n}\n\nreturn commons.text.sanitize(check) === commons.text.sanitize(labelText);\n\n},\"enabled\":false},{\"id\":\"implicit-label\",\"evaluate\":function (node, options) {\n\nvar label = commons.dom.findUp(node, 'label');\nif (label) {\n\treturn !!commons.text.accessibleText(label);\n}\nreturn false;\n\n}},{\"id\":\"multiple-label\",\"evaluate\":function (node, options) {\nvar labels = [].slice.call(document.querySelectorAll('label[for=\"' +\n\tcommons.utils.escapeSelector(node.id) + '\"]')),\n\tparent = node.parentNode;\n\nwhile (parent) {\n\tif (parent.tagName === 'LABEL' && labels.indexOf(parent) === -1) {\n\t\tlabels.push(parent);\n\t}\n\tparent = parent.parentNode;\n}\n\nthis.relatedNodes(labels);\nreturn labels.length > 1;\n\n}},{\"id\":\"title-only\",\"evaluate\":function (node, options) {\nvar labelText = commons.text.label(node);\nreturn !labelText && !!(node.getAttribute('title') || node.getAttribute('aria-describedby'));\n}},{\"id\":\"has-lang\",\"evaluate\":function (node, options) {\nreturn node.hasAttribute('lang') || node.hasAttribute('xml:lang');\n}},{\"id\":\"valid-lang\",\"options\":[\"aa\",\"ab\",\"ae\",\"af\",\"ak\",\"am\",\"an\",\"ar\",\"as\",\"av\",\"ay\",\"az\",\"ba\",\"be\",\"bg\",\"bh\",\"bi\",\"bm\",\"bn\",\"bo\",\"br\",\"bs\",\"ca\",\"ce\",\"ch\",\"co\",\"cr\",\"cs\",\"cu\",\"cv\",\"cy\",\"da\",\"de\",\"dv\",\"dz\",\"ee\",\"el\",\"en\",\"eo\",\"es\",\"et\",\"eu\",\"fa\",\"ff\",\"fi\",\"fj\",\"fo\",\"fr\",\"fy\",\"ga\",\"gd\",\"gl\",\"gn\",\"gu\",\"gv\",\"ha\",\"he\",\"hi\",\"ho\",\"hr\",\"ht\",\"hu\",\"hy\",\"hz\",\"ia\",\"id\",\"ie\",\"ig\",\"ii\",\"ik\",\"in\",\"io\",\"is\",\"it\",\"iu\",\"iw\",\"ja\",\"ji\",\"jv\",\"jw\",\"ka\",\"kg\",\"ki\",\"kj\",\"kk\",\"kl\",\"km\",\"kn\",\"ko\",\"kr\",\"ks\",\"ku\",\"kv\",\"kw\",\"ky\",\"la\",\"lb\",\"lg\",\"li\",\"ln\",\"lo\",\"lt\",\"lu\",\"lv\",\"mg\",\"mh\",\"mi\",\"mk\",\"ml\",\"mn\",\"mo\",\"mr\",\"ms\",\"mt\",\"my\",\"na\",\"nb\",\"nd\",\"ne\",\"ng\",\"nl\",\"nn\",\"no\",\"nr\",\"nv\",\"ny\",\"oc\",\"oj\",\"om\",\"or\",\"os\",\"pa\",\"pi\",\"pl\",\"ps\",\"pt\",\"qu\",\"rm\",\"rn\",\"ro\",\"ru\",\"rw\",\"sa\",\"sc\",\"sd\",\"se\",\"sg\",\"sh\",\"si\",\"sk\",\"sl\",\"sm\",\"sn\",\"so\",\"sq\",\"sr\",\"ss\",\"st\",\"su\",\"sv\",\"sw\",\"ta\",\"te\",\"tg\",\"th\",\"ti\",\"tk\",\"tl\",\"tn\",\"to\",\"tr\",\"ts\",\"tt\",\"tw\",\"ty\",\"ug\",\"uk\",\"ur\",\"uz\",\"ve\",\"vi\",\"vo\",\"wa\",\"wo\",\"xh\",\"yi\",\"yo\",\"za\",\"zh\",\"zu\"],\"evaluate\":function (node, options) {\nvar lang = (node.getAttribute('lang') || '').trim().toLowerCase();\nvar xmlLang = (node.getAttribute('xml:lang') || '').trim().toLowerCase();\nvar invalid = [];\n\n(options || []).forEach(function (cc) {\n\tcc = cc.toLowerCase();\n\tif (lang && (lang === cc || lang.indexOf(cc.toLowerCase() + '-') === 0)) {\n\t\tlang = null;\n\t}\n\tif (xmlLang && (xmlLang === cc || xmlLang.indexOf(cc.toLowerCase() + '-') === 0)) {\n\t\txmlLang = null;\n\t}\n});\n\nif (xmlLang) {\n\tinvalid.push('xml:lang=\"' + xmlLang + '\"');\n}\nif (lang) {\n\tinvalid.push('lang=\"' + lang + '\"');\n}\n\nif (invalid.length) {\n\tthis.data(invalid);\n\treturn true;\n}\n\nreturn false;\n}},{\"id\":\"dlitem\",\"evaluate\":function (node, options) {\nreturn node.parentNode.tagName === 'DL';\n\n\n}},{\"id\":\"has-listitem\",\"evaluate\":function (node, options) {\nvar children = node.children;\nif (children.length === 0) { return true; }\n\nfor (var i = 0; i < children.length; i++) {\n\tif (children[i].nodeName.toUpperCase() === 'LI') { return false; }\n}\n\nreturn true;\n\n\n}},{\"id\":\"listitem\",\"evaluate\":function (node, options) {\n\nif (['UL', 'OL'].indexOf(node.parentNode.nodeName.toUpperCase()) !== -1) {\n\treturn true;\n}\n\nreturn node.parentNode.getAttribute('role') === 'list';\n\n}},{\"id\":\"only-dlitems\",\"evaluate\":function (node, options) {\nvar child,\n\tnodeName,\n\tbad = [],\n\tchildren = node.childNodes,\n\thasNonEmptyTextNode = false;\n\nfor (var i = 0; i < children.length; i++) {\n\tchild = children[i];\n\tnodeName = child.nodeName.toUpperCase();\n\tif (child.nodeType === 1 && (nodeName !== 'DT' && nodeName !== 'DD'&&\n\t\tnodeName !== 'SCRIPT' && nodeName !== 'TEMPLATE')) {\n\t\tbad.push(child);\n\t} else if (child.nodeType === 3 && child.nodeValue.trim() !== '') {\n\t\thasNonEmptyTextNode = true;\n\t}\n}\nif (bad.length) {\n\tthis.relatedNodes(bad);\n}\n\nvar retVal = !!bad.length || hasNonEmptyTextNode;\nreturn retVal;\n\n}},{\"id\":\"only-listitems\",\"evaluate\":function (node, options) {\nvar child,\n\tnodeName,\n\tbad = [],\n\tchildren = node.childNodes,\n\thasNonEmptyTextNode = false;\n\nfor (var i = 0; i < children.length; i++) {\n\tchild = children[i];\n\tnodeName = child.nodeName.toUpperCase();\n\tif (child.nodeType === 1 && nodeName !== 'LI' && nodeName !== 'SCRIPT' && nodeName !== 'TEMPLATE') {\n\t\tbad.push(child);\n\t} else if (child.nodeType === 3 && child.nodeValue.trim() !== '') {\n\t\thasNonEmptyTextNode = true;\n\t}\n}\nif (bad.length) {\n\tthis.relatedNodes(bad);\n}\n\nreturn !!bad.length || hasNonEmptyTextNode;\n\n}},{\"id\":\"structured-dlitems\",\"evaluate\":function (node, options) {\nvar children = node.children;\nif ( !children || !children.length) { return false; }\n\nvar hasDt = false, hasDd = false, nodeName;\nfor (var i = 0; i < children.length; i++) {\n\tnodeName = children[i].nodeName.toUpperCase();\n\tif (nodeName === 'DT') { hasDt = true; }\n\tif (hasDt && nodeName === 'DD') { return false; }\n\tif (nodeName === 'DD') { hasDd = true; }\n}\n\nreturn hasDt || hasDd;\n\n}},{\"id\":\"caption\",\"evaluate\":function (node, options) {\nreturn !(node.querySelector('track[kind=captions]'));\n\n}},{\"id\":\"description\",\"evaluate\":function (node, options) {\nreturn !(node.querySelector('track[kind=descriptions]'));\n\n}},{\"id\":\"meta-viewport\",\"evaluate\":function (node, options) {\nvar params,\n\tcontent = node.getAttribute('content') || '',\n\tparsedParams = content.split(/[;,]/),\n\tresult = {};\n\nfor (var i = 0, l = parsedParams.length; i < l; i++) {\n\tparams = parsedParams[i].split('=');\n\tvar key = params.shift();\n\tif (key && params.length) {\n\t\tresult[key.trim()] = params.join('=').trim();\n\t}\n}\n\nif (result['maximum-scale'] && parseFloat(result['maximum-scale']) < 5) {\n\treturn false;\n}\n\nif (result['user-scalable'] === 'no') {\n\treturn false;\n}\n\n\nreturn true;\n}},{\"id\":\"header-present\",\"selector\":\"html\",\"evaluate\":function (node, options) {\nreturn !!node.querySelector('h1, h2, h3, h4, h5, h6, [role=\"heading\"]');\n\n}},{\"id\":\"heading-order\",\"evaluate\":function (node, options) {\nvar ariaHeadingLevel = node.getAttribute('aria-level');\n\nif (ariaHeadingLevel !== null) {\n\tthis.data(parseInt(ariaHeadingLevel, 10));\n\treturn true;\n}\n\nvar headingLevel = node.tagName.match(/H(\\d)/);\n\nif (headingLevel) {\n\tthis.data(parseInt(headingLevel[1], 10));\n\treturn true;\n}\n\nreturn true;\n\n},\"after\":function (results, options) {\nif (results.length < 2) { return results; }\n\nvar prevLevel = results[0].data;\n\nfor (var i = 1; i < results.length; i++) {\n\tif (results[i].result && results[i].data > (prevLevel + 1)) { results[i].result = false; }\n\tprevLevel = results[i].data;\n}\n\nreturn results;\n\n}},{\"id\":\"internal-link-present\",\"selector\":\"html\",\"evaluate\":function (node, options) {\nreturn !!node.querySelector('a[href^=\"#\"]');\n\n}},{\"id\":\"landmark\",\"selector\":\"html\",\"evaluate\":function (node, options) {\nreturn !!node.querySelector('[role=\"main\"]');\n\n}},{\"id\":\"meta-refresh\",\"evaluate\":function (node, options) {\nvar content = node.getAttribute('content') || '',\n\tparsedParams = content.split(/[;,]/);\n\nreturn (content === '' || parsedParams[0] === '0');\n\n}},{\"id\":\"region\",\"evaluate\":function (node, options) {\n//jshint latedef: false\n\nvar landmarkRoles = commons.aria.getRolesByType('landmark'),\n\tfirstLink = node.querySelector('a[href]');\n\nfunction isSkipLink(n) {\n\treturn firstLink &&\n\t\tcommons.dom.isFocusable(commons.dom.getElementByReference(firstLink, 'href')) &&\n\t\tfirstLink === n;\n}\n\nfunction isLandmark(n) {\n\tvar role = n.getAttribute('role');\n\treturn role && (landmarkRoles.indexOf(role) !== -1);\n}\n\nfunction checkRegion(n) {\n\tif (isLandmark(n)) { return null; }\n\tif (isSkipLink(n)) { return getViolatingChildren(n); }\n\tif (commons.dom.isVisible(n, true) &&\n\t\t(commons.text.visible(n, true, true) || commons.dom.isVisualContent(n))) { return n; }\n\treturn getViolatingChildren(n);\n}\nfunction getViolatingChildren(n) {\n\tvar children =  commons.utils.toArray(n.children);\n\tif (children.length === 0) { return []; }\n\treturn children.map(checkRegion)\n\t\t.filter(function (c) { return c !== null; })\n\t\t.reduce(function (a, b) { return a.concat(b); }, []);\n}\n\nvar v = getViolatingChildren(node);\nthis.relatedNodes(v);\nreturn !v.length;\n\n},\"after\":function (results, options) {\nreturn [results[0]];\n\n}},{\"id\":\"skip-link\",\"selector\":\"a[href]\",\"evaluate\":function (node, options) {\nreturn commons.dom.isFocusable(commons.dom.getElementByReference(node, 'href'));\n\n},\"after\":function (results, options) {\nreturn [results[0]];\n\n}},{\"id\":\"unique-frame-title\",\"evaluate\":function (node, options) {\nthis.data(node.title);\nreturn true;\n},\"after\":function (results, options) {\nvar titles = {};\nresults.forEach(function (r) {\n\ttitles[r.data] = titles[r.data] !== undefined ? ++titles[r.data] : 0;\n});\n\nreturn results.filter(function (r) {\n\treturn !!titles[r.data];\n});\n}},{\"id\":\"aria-label\",\"evaluate\":function (node, options) {\nvar label = node.getAttribute('aria-label');\nreturn !!(label ? commons.text.sanitize(label).trim() : '');\n}},{\"id\":\"aria-labelledby\",\"evaluate\":function (node, options) {\nvar results = commons.dom.idrefs(node, 'aria-labelledby');\nvar element, i, l = results.length;\n\nfor (i = 0; i < l; i++) {\n\telement = results[i];\n\tif (element && commons.text.accessibleText(element).trim()) {\n\t\treturn true;\n\t}\n}\n\nreturn false;\n\n}},{\"id\":\"button-has-visible-text\",\"evaluate\":function (node, options) {\nreturn commons.text.accessibleText(node).length > 0;\n\n},\"selector\":\"button, [role=\\\"button\\\"]:not(input)\"},{\"id\":\"doc-has-title\",\"evaluate\":function (node, options) {\nvar title = document.title;\nreturn !!(title ? commons.text.sanitize(title).trim() : '');\n}},{\"id\":\"duplicate-id\",\"evaluate\":function (node, options) {\nvar matchingNodes = document.querySelectorAll('[id=\"' + commons.utils.escapeSelector(node.id) + '\"]');\nvar related = [];\nfor (var i = 0; i < matchingNodes.length; i++) {\n\tif (matchingNodes[i] !== node) {\n\t\trelated.push(matchingNodes[i]);\n\t}\n}\nif (related.length) {\n\tthis.relatedNodes(related);\n}\nthis.data(node.getAttribute('id'));\n\nreturn (matchingNodes.length <= 1);\n\n},\"after\":function (results, options) {\nvar uniqueIds = [];\nreturn results.filter(function (r) {\n\tif (uniqueIds.indexOf(r.data) === -1) {\n\t\tuniqueIds.push(r.data);\n\t\treturn true;\n\t}\n\treturn false;\n});\n\n}},{\"id\":\"exists\",\"evaluate\":function (node, options) {\nreturn true;\n}},{\"id\":\"has-alt\",\"evaluate\":function (node, options) {\nreturn node.hasAttribute('alt');\n}},{\"id\":\"has-visible-text\",\"evaluate\":function (node, options) {\nreturn commons.text.accessibleText(node).length > 0;\n\n}},{\"id\":\"non-empty-alt\",\"evaluate\":function (node, options) {\nvar label = node.getAttribute('alt');\nreturn !!(label ? commons.text.sanitize(label).trim() : '');\n}},{\"id\":\"non-empty-if-present\",\"evaluate\":function (node, options) {\nvar label = node.getAttribute('value');\nthis.data(label);\nreturn label === null || commons.text.sanitize(label).trim() !== '';\n\n},\"selector\":\"[type=\\\"submit\\\"], [type=\\\"reset\\\"]\"},{\"id\":\"non-empty-title\",\"evaluate\":function (node, options) {\nvar title = node.getAttribute('title');\nreturn !!(title ? commons.text.sanitize(title).trim() : '');\n\n}},{\"id\":\"non-empty-value\",\"evaluate\":function (node, options) {\nvar label = node.getAttribute('value');\nreturn !!(label ? commons.text.sanitize(label).trim() : '');\n\n},\"selector\":\"[type=\\\"button\\\"]\"},{\"id\":\"role-none\",\"evaluate\":function (node, options) {\nreturn node.getAttribute('role') === 'none';\n}},{\"id\":\"role-presentation\",\"evaluate\":function (node, options) {\nreturn node.getAttribute('role') === 'presentation';\n}},{\"id\":\"cell-no-header\",\"evaluate\":function (node, options) {\n\n\nvar row, cell,\n\tbadCells = [];\n\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (commons.table.isDataCell(cell) && (!commons.aria.label(cell) && !commons.table.getHeaders(cell).length)) {\n\t\t\tbadCells.push(cell);\n\t\t}\n\t}\n}\n\nif (badCells.length) {\n\tthis.relatedNodes(badCells);\n\treturn true;\n}\n\nreturn false;\n\n}},{\"id\":\"consistent-columns\",\"evaluate\":function (node, options) {\nvar table = commons.table.toArray(node);\nvar relatedNodes = [];\nvar expectedWidth;\nfor (var i = 0, length = table.length; i < length; i++) {\n\tif (i === 0) {\n\t\texpectedWidth = table[i].length;\n\t} else if (expectedWidth !== table[i].length) {\n\t\trelatedNodes.push(node.rows[i]);\n\t}\n}\n\nreturn !relatedNodes.length;\n\n}},{\"id\":\"has-caption\",\"evaluate\":function (node, options) {\nreturn !!node.caption;\n}},{\"id\":\"has-summary\",\"evaluate\":function (node, options) {\nreturn !!node.summary;\n}},{\"id\":\"has-th\",\"evaluate\":function (node, options) {\n\nvar row, cell,\n\tbadCells = [];\n\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (cell.nodeName.toUpperCase() === 'TH') {\n\t\t\tbadCells.push(cell);\n\t\t}\n\t}\n}\n\nif (badCells.length) {\n\tthis.relatedNodes(badCells);\n\treturn true;\n}\n\nreturn false;\n}},{\"id\":\"headers-attr-reference\",\"evaluate\":function (node, options) {\nvar row, cell, headerCells,\n\tbadHeaders = [];\n\nfunction checkHeader(header) {\n\tif (!header || !commons.text.accessibleText(header)) {\n\t\tbadHeaders.push(cell);\n\t}\n}\n\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\theaderCells = commons.dom.idrefs(cell, 'headers');\n\t\tif (headerCells.length) {\n\t\t\theaderCells.forEach(checkHeader);\n\t\t}\n\t}\n}\n\nif (badHeaders.length) {\n\tthis.relatedNodes(badHeaders);\n\treturn true;\n}\n\nreturn false;\n\n}},{\"id\":\"headers-visible-text\",\"evaluate\":function (node, options) {\n\nvar row, cell,\n\tbadHeaders = [];\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (commons.table.isHeader(cell) && !commons.text.accessibleText(cell)) {\n\t\t\tbadHeaders.push(cell);\n\t\t}\n\t}\n}\n\nif (badHeaders.length) {\n\tthis.relatedNodes(badHeaders);\n\treturn true;\n}\n\nreturn false;\n\n}},{\"id\":\"html4-scope\",\"evaluate\":function (node, options) {\n\nif (commons.dom.isHTML5(document)) {\n\treturn false;\n}\n\nreturn node.nodeName.toUpperCase() === 'TH' || node.nodeName.toUpperCase() === 'TD';\n}},{\"id\":\"html5-scope\",\"evaluate\":function (node, options) {\n\nif (!commons.dom.isHTML5(document)) {\n\treturn false;\n}\n\nreturn node.nodeName.toUpperCase() === 'TH';\n}},{\"id\":\"no-caption\",\"evaluate\":function (node, options) {\nreturn !(node.caption || {}).textContent;\n},\"enabled\":false},{\"id\":\"rowspan\",\"evaluate\":function (node, options) {\nvar row, cell,\n\tbadCells = [];\n\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (cell.rowSpan !== 1) {\n\t\t\tbadCells.push(cell);\n\t\t}\n\t}\n}\n\nif (badCells.length) {\n\tthis.relatedNodes(badCells);\n\treturn true;\n}\n\nreturn false;\n}},{\"id\":\"same-caption-summary\",\"selector\":\"table\",\"evaluate\":function (node, options) {\nreturn !!(node.summary && node.caption) && node.summary === commons.text.accessibleText(node.caption);\n\n}},{\"id\":\"scope-value\",\"evaluate\":function (node, options) {\nvar value = node.getAttribute('scope');\nreturn value !== 'row' && value !== 'col';\n}},{\"id\":\"th-headers-attr\",\"evaluate\":function (node, options) {\n\nvar row, cell,\n\theadersTH = [];\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (cell.nodeName.toUpperCase() === 'TH' && cell.getAttribute('headers')) {\n\t\t\theadersTH.push(cell);\n\t\t}\n\t}\n}\n\nif (headersTH.length) {\n\tthis.relatedNodes(headersTH);\n\treturn true;\n}\n\nreturn false;\n}},{\"id\":\"th-scope\",\"evaluate\":function (node, options) {\n\nvar row, cell,\n\tnoScopeTH = [];\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (cell.nodeName.toUpperCase() === 'TH' && !cell.getAttribute('scope')) {\n\t\t\tnoScopeTH.push(cell);\n\t\t}\n\t}\n}\n\nif (noScopeTH.length) {\n\tthis.relatedNodes(noScopeTH);\n\treturn true;\n}\n\nreturn false;\n}},{\"id\":\"th-single-row-column\",\"evaluate\":function (node, options) {\n\nvar row, cell, position,\n\trowHeaders = [],\n\tcolumnHeaders = [];\n\nfor (var rowIndex = 0, rowLength = node.rows.length; rowIndex < rowLength; rowIndex++) {\n\trow = node.rows[rowIndex];\n\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcell = row.cells[cellIndex];\n\t\tif (cell.nodeName) {\n\t\t\tif (commons.table.isColumnHeader(cell) && columnHeaders.indexOf(rowIndex) === -1) {\n\t\t\t\tcolumnHeaders.push(rowIndex);\n\t\t\t} else if (commons.table.isRowHeader(cell)) {\n\t\t\t\tposition = commons.table.getCellPosition(cell);\n\t\t\t\tif (rowHeaders.indexOf(position.x) === -1) {\n\t\t\t\t\trowHeaders.push(position.x);\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n}\n\nif (columnHeaders.length > 1 || rowHeaders.length > 1) {\n\treturn true;\n}\n\nreturn false;\n}}],\"commons\":(function () {\n\n/*exported commons */\nvar commons = {};\n\nvar aria = commons.aria = {},\n\tlookupTables = aria._lut = {};\n\nlookupTables.attributes = {\n\t'aria-activedescendant': {\n\t\ttype: 'idref'\n\t},\n\t'aria-atomic': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-autocomplete': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['inline', 'list', 'both', 'none']\n\t},\n\t'aria-busy': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-checked': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['true', 'false', 'mixed', 'undefined']\n\t},\n\t'aria-colcount': {\n\t\ttype: 'int'\n\t},\n\t'aria-colindex': {\n\t\ttype: 'int'\n\t},\n\t'aria-colspan': {\n\t\ttype: 'int'\n\t},\n\t'aria-controls': {\n\t\ttype: 'idrefs'\n\t},\n\t'aria-describedby': {\n\t\ttype: 'idrefs'\n\t},\n\t'aria-disabled': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-dropeffect': {\n\t\ttype: 'nmtokens',\n\t\tvalues: ['copy', 'move', 'reference', 'execute', 'popup', 'none']\n\t},\n\t'aria-expanded': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['true', 'false', 'undefined']\n\t},\n\t'aria-flowto': {\n\t\ttype: 'idrefs'\n\t},\n\t'aria-grabbed': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['true', 'false', 'undefined']\n\t},\n\t'aria-haspopup': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-hidden': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-invalid': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['true', 'false', 'spelling', 'grammar']\n\t},\n\t'aria-label': {\n\t\ttype: 'string'\n\t},\n\t'aria-labelledby': {\n\t\ttype: 'idrefs'\n\t},\n\t'aria-level': {\n\t\ttype: 'int'\n\t},\n\t'aria-live': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['off', 'polite', 'assertive']\n\t},\n\t'aria-multiline': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-multiselectable': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-orientation' : {\n\t\ttype : 'nmtoken',\n\t\tvalues : ['horizontal', 'vertical']\n\t},\n\t'aria-owns': {\n\t\ttype: 'idrefs'\n\t},\n\t'aria-posinset': {\n\t\ttype: 'int'\n\t},\n\t'aria-pressed': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['true', 'false', 'mixed', 'undefined']\n\t},\n\t'aria-readonly': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-relevant': {\n\t\ttype: 'nmtokens',\n\t\tvalues: ['additions', 'removals', 'text', 'all']\n\t},\n\t'aria-required': {\n\t\ttype: 'boolean',\n\t\tvalues: ['true', 'false']\n\t},\n\t'aria-rowcount': {\n\t\ttype: 'int'\n\t},\n\t'aria-rowindex': {\n\t\ttype: 'int'\n\t},\n\t'aria-rowspan': {\n\t\ttype: 'int'\n\t},\n\t'aria-selected': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['true', 'false', 'undefined']\n\t},\n\t'aria-setsize': {\n\t\ttype: 'int'\n\t},\n\t'aria-sort': {\n\t\ttype: 'nmtoken',\n\t\tvalues: ['ascending', 'descending', 'other', 'none']\n\t},\n\t'aria-valuemax': {\n\t\ttype: 'decimal'\n\t},\n\t'aria-valuemin': {\n\t\ttype: 'decimal'\n\t},\n\t'aria-valuenow': {\n\t\ttype: 'decimal'\n\t},\n\t'aria-valuetext': {\n\t\ttype: 'string'\n\t}\n};\n\nlookupTables.globalAttributes = [\n\t'aria-atomic', 'aria-busy', 'aria-controls', 'aria-describedby',\n\t'aria-disabled', 'aria-dropeffect', 'aria-flowto', 'aria-grabbed',\n\t'aria-haspopup', 'aria-hidden', 'aria-invalid', 'aria-label',\n\t'aria-labelledby', 'aria-live', 'aria-owns', 'aria-relevant'\n];\n\nlookupTables.role = {\n\t'alert': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'alertdialog': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'application': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'article': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['article']\n\t},\n\t'banner': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'button': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded', 'aria-pressed']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null,\n\t\timplicit: ['button', 'input[type=\"button\"]', 'input[type=\"image\"]']\n\t},\n\t'cell': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-colindex', 'aria-colspan', 'aria-rowindex', 'aria-rowspan']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['row']\n\t},\n\t'checkbox': {\n\t\ttype: 'widget',\n\t\tattributes:  {\n\t\t\trequired: ['aria-checked']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null,\n\t\timplicit: ['input[type=\"checkbox\"]']\n\t},\n\t'columnheader': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded', 'aria-sort', 'aria-readonly', 'aria-selected', 'aria-required']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['row']\n\t},\n\t'combobox': {\n\t\ttype: 'composite',\n\t\tattributes:  {\n\t\t\trequired: ['aria-expanded'],\n\t\t\tallowed: ['aria-autocomplete', 'aria-required', 'aria-activedescendant']\n\t\t},\n\t\towned: {\n\t\t\tall: ['listbox', 'textbox']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'command': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t},\n\t'complementary': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['aside']\n\t},\n\t'composite': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t},\n\t'contentinfo': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'definition': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'dialog': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['dialog']\n\t},\n\t'directory': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null\n\t},\n\t'document': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['body']\n\t},\n\t'form': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'grid': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-level', 'aria-multiselectable', 'aria-readonly', 'aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tone: ['rowgroup', 'row']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'gridcell': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-selected', 'aria-readonly', 'aria-expanded', 'aria-required']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['row']\n\t},\n\t'group': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['details']\n\t},\n\t'heading': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-level', 'aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null,\n\t\timplicit: ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']\n\t},\n\t'img': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['img']\n\t},\n\t'input': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t},\n\t'landmark': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t},\n\t'link': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null,\n\t\timplicit: ['a[href]']\n\t},\n\t'list': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tall: ['listitem']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['ol', 'ul']\n\t},\n\t'listbox': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-multiselectable', 'aria-required', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tall: ['option']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['select']\n\t},\n\t'listitem': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-level', 'aria-posinset', 'aria-setsize', 'aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['list'],\n\t\timplicit: ['li']\n\t},\n\t'log': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'main': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'marquee': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'math': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'menu': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tone: ['menuitem', 'menuitemradio', 'menuitemcheckbox']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'menubar': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'menuitem': {\n\t\ttype: 'widget',\n\t\tattributes: null,\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['menu', 'menubar']\n\t},\n\t'menuitemcheckbox': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\trequired: ['aria-checked']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['menu', 'menubar']\n\t},\n\t'menuitemradio': {\n\t\ttype: 'widget',\n\t\tattributes:  {\n\t\t\tallowed: ['aria-selected', 'aria-posinset', 'aria-setsize'],\n\t\t\trequired: ['aria-checked']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['menu', 'menubar']\n\t},\n\t'navigation': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'none': {\n\t\ttype: 'structure',\n\t\tattributes: null,\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'note': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'option': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-selected', 'aria-posinset', 'aria-setsize', 'aria-checked']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['listbox']\n\t},\n\t'presentation': {\n\t\ttype: 'structure',\n\t\tattributes: null,\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'progressbar': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-valuetext', 'aria-valuenow', 'aria-valuemax', 'aria-valuemin']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'radio': {\n\t\ttype: 'widget',\n\t\tattributes:  {\n\t\t\tallowed: ['aria-selected', 'aria-posinset', 'aria-setsize'],\n\t\t\trequired: ['aria-checked']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null,\n\t\timplicit: ['input[type=\"radio\"]']\n\t},\n\t'radiogroup': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-required', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tall: ['radio']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'range': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t},\n\t'region': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['section']\n\t},\n\t'roletype': {\n\t\ttype: 'abstract'\n\t},\n\t'row': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-level', 'aria-selected', 'aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tone: ['cell', 'columnheader', 'rowheader', 'gridcell']\n\t\t},\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext:  ['rowgroup', 'grid', 'treegrid', 'table']\n\t},\n\t'rowgroup': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tall: ['row']\n\t\t},\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext:  ['grid', 'table']\n\t},\n\t'rowheader': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-sort', 'aria-required', 'aria-readonly', 'aria-expanded', 'aria-selected']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['row']\n\t},\n\t'scrollbar': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\trequired: ['aria-controls', 'aria-orientation', 'aria-valuenow', 'aria-valuemax', 'aria-valuemin'],\n\t\t\tallowed: ['aria-valuetext']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'search': {\n\t\ttype: 'landmark',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'searchbox': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-autocomplete', 'aria-multiline', 'aria-readonly', 'aria-required']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['input[type=\"search\"]']\n\t},\n\t'section': {\n\t\tnameFrom: ['author', 'contents'],\n\t\ttype: 'abstract'\n\t},\n\t'sectionhead': {\n\t\tnameFrom: ['author', 'contents'],\n\t\ttype: 'abstract'\n\t},\n\t'select': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t},\n\t'separator': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded', 'aria-orientation']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'slider': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-valuetext', 'aria-orientation'],\n\t\t\trequired: ['aria-valuenow', 'aria-valuemax', 'aria-valuemin']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'spinbutton': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-valuetext', 'aria-required'],\n\t\t\trequired: ['aria-valuenow', 'aria-valuemax', 'aria-valuemin']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'status': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['output']\n\t},\n\t'structure': {\n\t\ttype: 'abstract'\n\t},\n\t'switch': {\n\t\ttype: 'widget',\n\t\tattributes:  {\n\t\t\trequired: ['aria-checked']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null\n\t},\n\t'tab': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-selected', 'aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['tablist']\n\t},\n\t'table': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-colcount', 'aria-rowcount']\n\t\t},\n\t\towned: {\n\t\t\tone: ['rowgroup', 'row']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['table']\n\t},\n\t'tablist': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded', 'aria-level', 'aria-multiselectable']\n\t\t},\n\t\towned: {\n\t\t\tall: ['tab']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'tabpanel': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'text': {\n\t\ttype: 'structure',\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null\n\t},\n\t'textbox': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-autocomplete', 'aria-multiline', 'aria-readonly', 'aria-required']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['input[type=\"text\"]', 'input:not([type])']\n\t},\n\t'timer': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'toolbar': {\n\t\ttype: 'structure',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author'],\n\t\tcontext: null,\n\t\timplicit: ['menu[type=\"toolbar\"]']\n\t},\n\t'tooltip': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-expanded']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: null\n\t},\n\t'tree': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-multiselectable', 'aria-required', 'aria-expanded']\n\t\t},\n\t\towned: {\n\t\t\tall: ['treeitem']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'treegrid': {\n\t\ttype: 'composite',\n\t\tattributes: {\n\t\t\tallowed: ['aria-activedescendant', 'aria-expanded', 'aria-level', 'aria-multiselectable',\n\t\t\t\t'aria-readonly', 'aria-required']\n\t\t},\n\t\towned: {\n\t\t\tall: ['treeitem']\n\t\t},\n\t\tnameFrom: ['author'],\n\t\tcontext: null\n\t},\n\t'treeitem': {\n\t\ttype: 'widget',\n\t\tattributes: {\n\t\t\tallowed: ['aria-checked', 'aria-selected', 'aria-expanded', 'aria-level', 'aria-posinset', 'aria-setsize']\n\t\t},\n\t\towned: null,\n\t\tnameFrom: ['author', 'contents'],\n\t\tcontext: ['treegrid', 'tree']\n\t},\n\t'widget': {\n\t\ttype: 'abstract'\n\t},\n\t'window': {\n\t\tnameFrom: ['author'],\n\t\ttype: 'abstract'\n\t}\n};\n\nvar color = {};\ncommons.color = color;\n\n/*exported dom */\nvar dom = commons.dom = {};\n\n/*exported table */\nvar table = commons.table = {};\n\n/*exported text */\nvar text = commons.text = {};\n/*exported utils */\n/*global axe */\nvar utils = commons.utils = {};\n\nutils.escapeSelector = axe.utils.escapeSelector;\nutils.matchesSelector = axe.utils.matchesSelector;\nutils.clone = axe.utils.clone;\n\n/*global aria, utils, lookupTables */\n\n/**\n * Get required attributes for a given role\n * @param  {String} role The role to check\n * @return {Array}\n */\naria.requiredAttr = function (role) {\n\t'use strict';\n\tvar roles = lookupTables.role[role],\n\t\tattr = roles && roles.attributes && roles.attributes.required;\n\treturn attr || [];\n};\n\n/**\n * Get allowed attributes for a given role\n * @param  {String} role The role to check\n * @return {Array}\n */\naria.allowedAttr = function (role) {\n\t'use strict';\n\tvar roles = lookupTables.role[role],\n\t\tattr = (roles && roles.attributes && roles.attributes.allowed) || [],\n\t\trequiredAttr = (roles && roles.attributes && roles.attributes.required) || [];\n\treturn attr.concat(lookupTables.globalAttributes).concat(requiredAttr);\n};\n\n/**\n * Check if an aria- attribute name is valid\n * @param  {String} att The attribute name\n * @return {Boolean}\n */\naria.validateAttr = function (att) {\n\t'use strict';\n\treturn !!lookupTables.attributes[att];\n};\n\n/**\n * Validate the value of an ARIA attribute\n * @param  {HTMLElement} node The element to check\n * @param  {String} attr The name of the attribute\n * @return {Boolean}\n */\naria.validateAttrValue = function (node, attr) {\n\t//jshint maxcomplexity: 12\n\t'use strict';\n\tvar ids, index, length, matches,\n\t\tdoc = document,\n\t\tvalue = node.getAttribute(attr),\n\t\tattrInfo = lookupTables.attributes[attr];\n\n\tif (!attrInfo) {\n\t\treturn true;\n\n\t} else if (attrInfo.values) {\n\t\tif (typeof value === 'string' && attrInfo.values.indexOf(value.toLowerCase()) !== -1) {\n\t\t\treturn true;\n\t\t}\n\t\treturn false;\n\t}\n\n\tswitch (attrInfo.type) {\n\tcase 'idref':\n\t\treturn !!(value && doc.getElementById(value));\n\n\tcase 'idrefs':\n\t\tids = utils.tokenList(value);\n\t\tfor (index = 0, length = ids.length; index < length; index++) {\n\t\t\tif (ids[index] && !doc.getElementById(ids[index])) {\n\t\t\t\treturn false;\n\t\t\t}\n\t\t}\n\t\t// not valid if there are no elements\n\t\treturn !!ids.length;\n\n\tcase 'string':\n\t\t// anything goes\n\t\treturn true;\n\n\tcase 'decimal':\n\t\tmatches = value.match(/^[-+]?([0-9]*)\\.?([0-9]*)$/);\n\t\treturn !!(matches && (matches[1] || matches[2]));\n\n\tcase 'int':\n\t\treturn (/^[-+]?[0-9]+$/).test(value);\n\t}\n};\n\n/*global aria, dom, text */\n/**\n * Gets the accessible ARIA label text of a given element\n * @see http://www.w3.org/WAI/PF/aria/roles#namecalculation\n * @param  {HTMLElement} node The element to test\n * @return {Mixed}      String of visible text, or `null` if no label is found\n */\naria.label = function (node) {\n\tvar ref, candidate;\n\n\tif (node.getAttribute('aria-labelledby')) {\n\t\t// aria-labelledby\n\t\tref = dom.idrefs(node, 'aria-labelledby');\n\t\tcandidate = ref.map(function (thing) {\n\t\t\treturn thing ? text.visible(thing, true) : '';\n\t\t}).join(' ').trim();\n\n\t\tif (candidate) {\n\t\t\treturn candidate;\n\t\t}\n\t}\n\n\t// aria-label\n\tcandidate = node.getAttribute('aria-label');\n\tif (candidate) {\n\t\tcandidate = text.sanitize(candidate).trim();\n\t\tif (candidate) {\n\t\t\treturn candidate;\n\t\t}\n\t}\n\n\treturn null;\n};\n\n/*global aria, lookupTables, utils */\n\n/**\n * Check if a given role is valid\n * @param  {String}  role The role to check\n * @return {Boolean}\n */\naria.isValidRole = function (role) {\n\t'use strict';\n\tif (lookupTables.role[role]) {\n\t\treturn true;\n\t}\n\n\treturn false;\n};\n\n/**\n * Get the roles that get name from contents\n * @return {Array}           Array of roles that match the type\n */\naria.getRolesWithNameFromContents = function () {\n\treturn Object.keys(lookupTables.role).filter(function (r) {\n\t\treturn lookupTables.role[r].nameFrom &&\n\t\t\tlookupTables.role[r].nameFrom.indexOf('contents') !== -1;\n\t});\n};\n\n/**\n * Get the roles that have a certain \"type\"\n * @param  {String} roleType The roletype to check\n * @return {Array}           Array of roles that match the type\n */\naria.getRolesByType = function (roleType) {\n\treturn Object.keys(lookupTables.role).filter(function (r) {\n\t\treturn lookupTables.role[r].type === roleType;\n\t});\n};\n\n/**\n * Get the \"type\" of role; either widget, composite, abstract, landmark or `null`\n * @param  {String} role The role to check\n * @return {Mixed}       String if a matching role and its type are found, otherwise `null`\n */\naria.getRoleType = function (role) {\n\tvar r = lookupTables.role[role];\n\n\treturn (r && r.type) || null;\n};\n\n/**\n * Get the required owned (children) roles for a given role\n * @param  {String} role The role to check\n * @return {Mixed}       Either an Array of required owned elements or `null` if there are none\n */\naria.requiredOwned = function (role) {\n\t'use strict';\n\tvar owned = null,\n\t\troles = lookupTables.role[role];\n\n\tif (roles) {\n\t\towned = utils.clone(roles.owned);\n\t}\n\treturn owned;\n};\n\n/**\n * Get the required context (parent) roles for a given role\n * @param  {String} role The role to check\n * @return {Mixed}       Either an Array of required context elements or `null` if there are none\n */\naria.requiredContext = function (role) {\n\t'use strict';\n\tvar context = null,\n\t\troles = lookupTables.role[role];\n\n\tif (roles) {\n\t\tcontext = utils.clone(roles.context);\n\t}\n\treturn context;\n};\n\n/**\n * Get a list of CSS selectors of nodes that have an implicit role\n * @param  {String} role The role to check\n * @return {Mixed}       Either an Array of CSS selectors or `null` if there are none\n */\naria.implicitNodes = function (role) {\n\t'use strict';\n\n\tvar implicit = null,\n\t\troles = lookupTables.role[role];\n\n\tif (roles && roles.implicit) {\n\t\timplicit = utils.clone(roles.implicit);\n\t}\n\treturn implicit;\n};\n\n/**\n * Get the implicit role for a given node\n * @param  {HTMLElement} node The node to test\n * @return {Mixed}      Either the role or `null` if there is none\n */\naria.implicitRole = function (node) {\n\t'use strict';\n\n\tvar role, r, candidate,\n\t\troles = lookupTables.role;\n\n\tfor (role in roles) {\n\t\tif (roles.hasOwnProperty(role)) {\n\t\t\tr = roles[role];\n\t\t\tif (r.implicit) {\n\t\t\t\tfor (var index = 0, length = r.implicit.length; index < length; index++) {\n\t\t\t\t\tcandidate = r.implicit[index];\n\t\t\t\t\tif (utils.matchesSelector(node, candidate)) {\n\t\t\t\t\t\treturn role;\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n\n\treturn null;\n};\n\n/*global color */\n\n/**\n * @constructor\n * @param {number} red\n * @param {number} green\n * @param {number} blue\n * @param {number} alpha\n */\ncolor.Color = function (red, green, blue, alpha) {\n\t/** @type {number} */\n\tthis.red = red;\n\n\t/** @type {number} */\n\tthis.green = green;\n\n\t/** @type {number} */\n\tthis.blue = blue;\n\n\t/** @type {number} */\n\tthis.alpha = alpha;\n\n\t/**\n\t * Provide the hex string value for the color\n\t * @return {string}\n\t */\n\tthis.toHexString = function () {\n\t\tvar redString = Math.round(this.red).toString(16);\n\t\tvar greenString = Math.round(this.green).toString(16);\n\t\tvar blueString = Math.round(this.blue).toString(16);\n\t\treturn '#' + (this.red > 15.5 ? redString : '0' + redString) +\n\t\t\t(this.green > 15.5 ? greenString : '0' + greenString) +\n\t\t\t(this.blue > 15.5 ? blueString : '0' + blueString);\n\t};\n\t\n\tvar rgbRegex = /^rgb\\((\\d+), (\\d+), (\\d+)\\)$/;\n\tvar rgbaRegex = /^rgba\\((\\d+), (\\d+), (\\d+), (\\d*(\\.\\d+)?)\\)/;\n\n\t/** \n\t * Set the color value based on a CSS RGB/RGBA string\n\t * @param  {string}  rgb  The string value\n\t */\n\tthis.parseRgbString = function (colorString) {\n\t\tvar match = colorString.match(rgbRegex);\n\n\t\tif (match) {\n\t\t\tthis.red = parseInt(match[1], 10);\n\t\t\tthis.green = parseInt(match[2], 10);\n\t\t\tthis.blue = parseInt(match[3], 10);\n\t\t\tthis.alpha = 1;\n\t\t\treturn;\n\t\t}\n\n\t\tmatch = colorString.match(rgbaRegex);\n\t\tif (match) {\n\t\t\tthis.red = parseInt(match[1], 10);\n\t\t\tthis.green = parseInt(match[2], 10);\n\t\t\tthis.blue = parseInt(match[3], 10);\n\t\t\tthis.alpha = parseFloat(match[4]);\n\t\t\treturn;\n\t\t}\n\t};\n\n\t/**\n\t * Get the relative luminance value\n\t * using algorithm from http://www.w3.org/WAI/GL/wiki/Relative_luminance\n\t * @return {number} The luminance value, ranges from 0 to 1\n\t */\n\tthis.getRelativeLuminance = function () {\n\t\tvar rSRGB = this.red / 255;\n\t\tvar gSRGB = this.green / 255;\n\t\tvar bSRGB = this.blue / 255;\n\n\t\tvar r = rSRGB <= 0.03928 ? rSRGB / 12.92 : Math.pow(((rSRGB + 0.055) / 1.055), 2.4);\n\t\tvar g = gSRGB <= 0.03928 ? gSRGB / 12.92 : Math.pow(((gSRGB + 0.055) / 1.055), 2.4);\n\t\tvar b = bSRGB <= 0.03928 ? bSRGB / 12.92 : Math.pow(((bSRGB + 0.055) / 1.055), 2.4);\n\n\t\treturn 0.2126 * r + 0.7152 * g + 0.0722 * b;\n\t};\n};\n\n/**\n * Combine the two given color according to alpha blending.\n * @param {Color} fgColor\n * @param {Color} bgColor\n * @return {Color}\n */\ncolor.flattenColors = function (fgColor, bgColor) {\n\tvar alpha = fgColor.alpha;\n\tvar r = ((1 - alpha) * bgColor.red) + (alpha * fgColor.red);\n\tvar g  = ((1 - alpha) * bgColor.green) + (alpha * fgColor.green);\n\tvar b = ((1 - alpha) * bgColor.blue) + (alpha * fgColor.blue);\n\tvar a = fgColor.alpha + (bgColor.alpha * (1 - fgColor.alpha));\n\n\treturn new color.Color(r, g, b, a);\n};\n\n/**\n * Get the contrast of two colors\n * @param  {Color}  bgcolor  Background color\n * @param  {Color}  fgcolor  Foreground color\n * @return {number} The contrast ratio\n */\ncolor.getContrast = function (bgColor, fgColor) {\n\tif (!fgColor || !bgColor) { return null; }\n\n\tif (fgColor.alpha < 1) {\n\t\tfgColor = color.flattenColors(fgColor, bgColor);\n\t}\n\n\tvar bL = bgColor.getRelativeLuminance();\n\tvar fL = fgColor.getRelativeLuminance();\n\n\treturn (Math.max(fL, bL) + 0.05) / (Math.min(fL, bL) + 0.05);\n};\n\n/**\n * Check whether certain text properties meet WCAG contrast rules\n * @param  {Color}  bgcolor  Background color\n * @param  {Color}  fgcolor  Foreground color\n * @param  {number}  fontSize  Font size of text, in pixels\n * @param  {boolean}  isBold  Whether the text is bold\n * @return {{isValid: boolean, contrastRatio: number}} \n */\ncolor.hasValidContrastRatio = function (bg, fg, fontSize, isBold) {\n\tvar contrast = color.getContrast(bg, fg);\n\tvar isSmallFont = (isBold && (Math.ceil(fontSize * 72) / 96) < 14) || (!isBold && (Math.ceil(fontSize * 72) / 96) < 18);\n\n\treturn {\n\t\tisValid: (isSmallFont && contrast >= 4.5) || (!isSmallFont && contrast >= 3),\n\t\tcontrastRatio: contrast\n\t};\n\n};\n\n/*global dom, color */\n/* jshint maxstatements: 32, maxcomplexity: 15 */\n//TODO dsturley: too complex, needs refactor!!\n\n/**\n * Returns the non-alpha-blended background color of a node, null if it's an image\n * @param {Element} node\n * @return {Color}\n */\nfunction getBackgroundForSingleNode(node) {\n\tvar bgColor,\n\t\tnodeStyle = window.getComputedStyle(node);\n\n\tif (nodeStyle.getPropertyValue('background-image') !== 'none') {\n\t\treturn null;\n\t}\n\n\tvar bgColorString = nodeStyle.getPropertyValue('background-color');\n\t//Firefox exposes unspecified background as 'transparent' rather than rgba(0,0,0,0)\n\tif (bgColorString === 'transparent') {\n\t\tbgColor = new color.Color(0, 0, 0, 0);\n\t} else {\n\t\tbgColor = new color.Color();\n\t\tbgColor.parseRgbString(bgColorString);\n\t}\n\tvar opacity = nodeStyle.getPropertyValue('opacity');\n\tbgColor.alpha = bgColor.alpha * opacity;\n\n\treturn bgColor;\n}\n\n/**\n * Determines whether an element has a fully opaque background, whether solid color or an image\n * @param {Element} node\n * @return {Boolean} false if the background is transparent, true otherwise\n */\ndom.isOpaque = function(node) {\n\tvar bgColor = getBackgroundForSingleNode(node);\n\tif (bgColor === null || bgColor.alpha === 1) {\n\t\treturn true;\n\t}\n\treturn false;\n};\n\n/**\n * Returns the elements that are visually \"above\" this one in z-index order where\n * supported at the position given inside the top-left corner of the provided\n * rectangle. Where not supported (IE < 10), returns the DOM parents.\n * @param {Element} node\n * @param {DOMRect} rect rectangle containing dimensions to consider\n * @return {Array} array of elements\n */\nvar getVisualParents = function(node, rect) {\n\tvar visualParents,\n\t\tthisIndex,\n\t\tparents = [],\n\t\tfallbackToVisual = false,\n\t\tcurrentNode = node,\n\t\tnodeStyle = window.getComputedStyle(currentNode),\n\t\tposVal, topVal, bottomVal, leftVal, rightVal;\n\n\twhile (currentNode !== null && (!dom.isOpaque(currentNode) || parseInt(nodeStyle.getPropertyValue('height'), 10) === 0)) {\n\t\t// If the element is positioned, we can't rely on DOM order to find visual parents\n\t\tposVal = nodeStyle.getPropertyValue('position');\n\t\ttopVal = nodeStyle.getPropertyValue('top');\n\t\tbottomVal = nodeStyle.getPropertyValue('bottom');\n\t\tleftVal = nodeStyle.getPropertyValue('left');\n\t\trightVal = nodeStyle.getPropertyValue('right');\n\t\tif ((posVal !== 'static' && posVal !== 'relative') ||\n\t\t\t(posVal === 'relative' &&\n\t\t\t\t(leftVal !== 'auto' ||\n\t\t\t\t\trightVal !== 'auto' ||\n\t\t\t\t\ttopVal !== 'auto' ||\n\t\t\t\t\tbottomVal !== 'auto'))) {\n\t\t\tfallbackToVisual = true;\n\t\t}\n\t\tcurrentNode = currentNode.parentElement;\n\t\tif (currentNode !== null) {\n\t\t\tnodeStyle = window.getComputedStyle(currentNode);\n\t\t\tif (parseInt(nodeStyle.getPropertyValue('height'), 10) !== 0) {\n\t\t\t\tparents.push(currentNode);\n\t\t\t}\n\t\t}\n\t}\n\n\tif (fallbackToVisual && dom.supportsElementsFromPoint(document)) {\n\t\tvisualParents = dom.elementsFromPoint(document,\n\t\t\tMath.ceil(rect.left + 1),\n\t\t\tMath.ceil(rect.top + 1));\n\t\tthisIndex = visualParents.indexOf(node);\n\n\t\t// if the element is not present; then something is obscuring it thus making calculation impossible\n\t\tif (thisIndex === -1) {\n\t\t\treturn null;\n\t\t}\n\n\t\tif (visualParents && (thisIndex < visualParents.length - 1)) {\n\t\t\tparents = visualParents.slice(thisIndex + 1);\n\t\t}\n\t}\n\n\treturn parents;\n};\n\n\n/**\n * Returns the flattened background color of an element, or null if it can't be determined because\n * there is no opaque ancestor element visually containing it, or because background images are used.\n * @param {Element} node\n * @param {Array} bgNodes array to which all encountered nodes should be appended\n * @param {Boolean} useScroll\n * @return {Color}\n */\n//TODO dsturley; why is this passing `bgNodes`?\ncolor.getBackgroundColor = function(node, bgNodes, useScroll) {\n\tvar parent, parentColor;\n\n\tvar bgColor = getBackgroundForSingleNode(node);\n\tif (bgNodes && (bgColor === null || bgColor.alpha !== 0)) {\n\t\tbgNodes.push(node);\n\t}\n\tif (bgColor === null || bgColor.alpha === 1) {\n\t\treturn bgColor;\n\t}\n\n\tif(useScroll) {\n\t\tnode.scrollIntoView();\n\t}\n\n\tvar rect = node.getBoundingClientRect(),\n\t\tcurrentNode = node,\n\t\tcolorStack = [{\n\t\t\tcolor: bgColor,\n\t\t\tnode: node\n\t\t}],\n\t\tparents = getVisualParents(currentNode, rect);\n\tif (!parents) {\n\t\treturn null;\n\t}\n\n\twhile (bgColor.alpha !== 1) {\n\t\tparent = parents.shift();\n\n\t\tif (!parent && currentNode.tagName !== 'HTML') {\n\t\t\treturn null;\n\t\t}\n\n\t\t//Assume white if top level is not specified\n\t\tif (!parent && currentNode.tagName === 'HTML') {\n\t\t\tparentColor = new color.Color(255, 255, 255, 1);\n\t\t} else {\n\n\t\t\tif (!dom.visuallyContains(node, parent)) {\n\t\t\t\treturn null;\n\t\t\t}\n\n\t\t\tparentColor = getBackgroundForSingleNode(parent);\n\t\t\tif (bgNodes && (parentColor === null || parentColor.alpha !== 0)) {\n\t\t\t\tbgNodes.push(parent);\n\t\t\t}\n\t\t\tif (parentColor === null) {\n\t\t\t\treturn null;\n\t\t\t}\n\t\t}\n\t\tcurrentNode = parent;\n\t\tbgColor = parentColor;\n\t\tcolorStack.push({\n\t\t\tcolor: bgColor,\n\t\t\tnode: currentNode\n\t\t});\n\t}\n\n\tvar currColorNode = colorStack.pop();\n\tvar flattenedColor = currColorNode.color;\n\n\twhile ((currColorNode = colorStack.pop()) !== undefined) {\n\t\tflattenedColor = color.flattenColors(currColorNode.color, flattenedColor);\n\t}\n\n\treturn flattenedColor;\n};\n\n/*global color */\n\n/**\n * Returns the flattened foreground color of an element, or null if it can't be determined because\n * of transparency\n * @param {Element} node\n * @param {Boolean} useScroll\n * @return {Color}\n */\ncolor.getForegroundColor = function (node, useScroll) {\n\tvar nodeStyle = window.getComputedStyle(node);\n\n\tvar fgColor = new color.Color();\n\tfgColor.parseRgbString(nodeStyle.getPropertyValue('color'));\n\tvar opacity = nodeStyle.getPropertyValue('opacity');\n\tfgColor.alpha = fgColor.alpha * opacity;\n\tif (fgColor.alpha === 1) { return fgColor; }\n\n\tvar bgColor = color.getBackgroundColor(node, [], useScroll);\n\tif (bgColor === null) { return null; }\n\n\treturn color.flattenColors(fgColor, bgColor);\n};\n\n/* global dom */\n\n/**\n * Returns true if the browser supports one of the methods to get elements from point\n * @param {Document} doc The HTML document\n * @return {Boolean}\n */\ndom.supportsElementsFromPoint = function (doc) {\n\tvar element = doc.createElement('x');\n\telement.style.cssText = 'pointer-events:auto';\n\treturn element.style.pointerEvents === 'auto' || !!doc.msElementsFromPoint;\n};\n\n\n/**\n * Returns the elements at a particular point in the viewport, in z-index order\n * @param {Document} doc The HTML document\n * @param {Element} x The x coordinate, as an integer\n * @param {Element} y The y coordinate, as an integer\n * @return {Array} Array of Elements\n */\ndom.elementsFromPoint = function (doc, x, y) {\n\tvar elements = [], previousPointerEvents = [], current, i, d;\n\n\tif (doc.msElementsFromPoint) {\n\t\tvar nl = doc.msElementsFromPoint(x, y);\n\t\treturn nl ? Array.prototype.slice.call(nl) : null;\n\t}\n\n\t// get all elements via elementFromPoint, and remove them from hit-testing in order\n\twhile ((current = doc.elementFromPoint(x, y)) && elements.indexOf(current) === -1 && current !== null) {\n\n\t\t// push the element and its current style\n\t\telements.push(current);\n\n\t\tpreviousPointerEvents.push({\n\t\t\tvalue: current.style.getPropertyValue('pointer-events'),\n\t\t\tpriority: current.style.getPropertyPriority('pointer-events')\n\t\t});\n\n\t\t// add \"pointer-events: none\", to get to the underlying element\n\t\tcurrent.style.setProperty('pointer-events', 'none', 'important');\n\n\t\tif (dom.isOpaque(current)) { break; }\n\t}\n\n\t// restore the previous pointer-events values\n\tfor (i = previousPointerEvents.length; !!(d = previousPointerEvents[--i]);) {\n\t\telements[i].style.setProperty('pointer-events', d.value ? d.value : '', d.priority);\n\t}\n\n\t// return our results\n\treturn elements;\n};\n\n/*global dom, utils */\n/**\n * recusively walk up the DOM, checking for a node which matches a selector\n *\n * **WARNING:** this should be used sparingly, as it's not even close to being performant\n *\n * @param {HTMLElement|String} element The starting HTMLElement\n * @param {String} selector The selector for the HTMLElement\n * @return {HTMLElement|null} Either the matching HTMLElement or `null` if there was no match\n */\ndom.findUp = function (element, target) {\n\t'use strict';\n\t/*jslint browser:true*/\n\n\tvar parent,\n\t\tmatches = document.querySelectorAll(target),\n\t\tlength = matches.length;\n\n\tif (!length) {\n\t\treturn null;\n\t}\n\n\tmatches = utils.toArray(matches);\n\n\tparent = element.parentNode;\n\t// recrusively walk up the DOM, checking each parent node\n\twhile (parent && matches.indexOf(parent) === -1) {\n\t\tparent = parent.parentNode;\n\t}\n\n\treturn parent;\n};\n\n/*global dom */\n\ndom.getElementByReference = function (node, attr) {\n\t'use strict';\n\n\tvar candidate,\n\t\tfragment = node.getAttribute(attr),\n\t\tdoc = document;\n\n\tif (fragment && fragment.charAt(0) === '#') {\n\t\tfragment = fragment.substring(1);\n\n\t\tcandidate = doc.getElementById(fragment);\n\t\tif (candidate) {\n\t\t\treturn candidate;\n\t\t}\n\n\t\tcandidate = doc.getElementsByName(fragment);\n\t\tif (candidate.length) {\n\t\t\treturn candidate[0];\n\t\t}\n\n\t}\n\n\treturn null;\n};\n/*global dom */\n/**\n * Get the coordinates of the element passed into the function relative to the document\n *\n * #### Returns\n *\n * Returns a `Object` with the following properties, which\n * each hold a value representing the pixels for each of the\n * respective coordinates:\n *\n * - `top`\n * - `right`\n * - `bottom`\n * - `left`\n * - `width`\n * - `height`\n *\n * @param {HTMLElement} el The HTMLElement\n */\ndom.getElementCoordinates = function (element) {\n\t'use strict';\n\n\tvar scrollOffset = dom.getScrollOffset(document),\n\t\txOffset = scrollOffset.left,\n\t\tyOffset = scrollOffset.top,\n\t\tcoords = element.getBoundingClientRect();\n\n\treturn {\n\t\ttop: coords.top + yOffset,\n\t\tright: coords.right + xOffset,\n\t\tbottom: coords.bottom + yOffset,\n\t\tleft: coords.left + xOffset,\n\n\t\twidth: coords.right - coords.left,\n\t\theight: coords.bottom - coords.top\n\t};\n};\n\n/*global dom */\n/**\n * Get the scroll offset of the document passed in\n *\n * @param {Document} element The element to evaluate, defaults to document\n * @return {Object} Contains the attributes `x` and `y` which contain the scroll offsets\n */\ndom.getScrollOffset = function (element) {\n\t'use strict';\n\n\tif (!element.nodeType && element.document) {\n\t\telement = element.document;\n\t}\n\n\t// 9 === Node.DOCUMENT_NODE\n\tif (element.nodeType === 9) {\n\t\tvar docElement = element.documentElement,\n\t\t\tbody = element.body;\n\n\t\treturn {\n\t\t\tleft: (docElement && docElement.scrollLeft || body && body.scrollLeft || 0),\n\t\t\ttop: (docElement && docElement.scrollTop || body && body.scrollTop || 0)\n\t\t};\n\t}\n\n\treturn {\n\t\tleft: element.scrollLeft,\n\t\ttop: element.scrollTop\n\t};\n};\n/*global dom */\n/**\n * Gets the width and height of the viewport; used to calculate the right and bottom boundaries of the viewable area.\n *\n * @api private\n * @param  {Object}  window The `window` object that should be measured\n * @return {Object}  Object with the `width` and `height` of the viewport\n */\ndom.getViewportSize = function (win) {\n\t'use strict';\n\n\tvar body,\n\t\tdoc = win.document,\n\t\tdocElement = doc.documentElement;\n\n\tif (win.innerWidth) {\n\t\treturn {\n\t\t\twidth: win.innerWidth,\n\t\t\theight: win.innerHeight\n\t\t};\n\t}\n\n\tif (docElement) {\n\t\treturn {\n\t\t\twidth: docElement.clientWidth,\n\t\t\theight: docElement.clientHeight\n\t\t};\n\n\t}\n\n\tbody = doc.body;\n\n\treturn {\n\t\twidth: body.clientWidth,\n\t\theight: body.clientHeight\n\t};\n};\n/*global dom, utils */\n\n/**\n * Get elements referenced via a space-separated token attribute; it will insert `null` for any Element that is not found\n * @param  {HTMLElement} node\n * @param  {String} attr The name of attribute\n * @return {Array}      Array of elements (or `null` if not found)\n */\ndom.idrefs = function (node, attr) {\n\t'use strict';\n\n\tvar index, length,\n\t\tdoc = document,\n\t\tresult = [],\n\t\tidrefs = node.getAttribute(attr);\n\n\tif (idrefs) {\n\t\tidrefs = utils.tokenList(idrefs);\n\t\tfor (index = 0, length = idrefs.length; index < length; index++) {\n\t\t\tresult.push(doc.getElementById(idrefs[index]));\n\t\t}\n\t}\n\n\treturn result;\n};\n/*global dom */\n/* jshint maxcomplexity: 20 */\n/**\n * Determines if an element is focusable\n * @param {HTMLelement} element The HTMLelement\n * @return {Boolean} The element's focusability status\n */\n\ndom.isFocusable = function (el) {\n\t'use strict';\n\n\tif (!el ||\n\t\tel.disabled ||\n\t\t(!dom.isVisible(el) && el.nodeName.toUpperCase() !== 'AREA')) {\n\t\treturn false;\n\t}\n\n\tswitch (el.nodeName.toUpperCase()) {\n\t\tcase 'A':\n\t\tcase 'AREA':\n\t\t\tif (el.href) {\n\t\t\t\treturn true;\n\t\t\t}\n\t\t\tbreak;\n\t\tcase 'INPUT':\n\t\t\treturn el.type !== 'hidden';\n\t\tcase 'TEXTAREA':\n\t\tcase 'SELECT':\n\t\tcase 'DETAILS':\n\t\tcase 'BUTTON':\n\t\t\treturn true;\n\t}\n\n\t// check if the tabindex is specified and a parseable number\n\tvar tabindex = el.getAttribute('tabindex');\n\tif (tabindex && !isNaN(parseInt(tabindex, 10))) {\n\t\treturn true;\n\t}\n\n\treturn false;\n};\n\n/*global dom */\ndom.isHTML5 = function (doc) {\n\tvar node = doc.doctype;\n\tif (node === null) {\n\t\treturn false;\n\t}\n\treturn node.name === 'html' && !node.publicId && !node.systemId;\n};\n/*global dom */\ndom.isNode = function (candidate) {\n\t'use strict';\n\treturn candidate instanceof Node;\n};\n\n/*global dom */\n\ndom.isOffscreen = function (element) {\n\t'use strict';\n\n\tvar leftBoundary,\n\t\tdocElement = document.documentElement,\n\t\tdir = window.getComputedStyle(document.body || docElement)\n\t\t\t.getPropertyValue('direction'),\n\t\tcoords = dom.getElementCoordinates(element);\n\n\t// bottom edge beyond\n\tif (coords.bottom < 0) {\n\t\treturn true;\n\t}\n\n\tif (dir === 'ltr') {\n\t\tif (coords.right < 0) {\n\t\t\treturn true;\n\t\t}\n\t} else {\n\n\t\tleftBoundary = Math.max(docElement.scrollWidth, dom.getViewportSize(window).width);\n\t\tif (coords.left > leftBoundary) {\n\t\t\treturn true;\n\t\t}\n\t}\n\n\treturn false;\n\n};\n\n/*global dom */\n/*jshint maxcomplexity: 11 */\n\n/**\n * Determines if an element is hidden with the clip rect technique\n * @param  {String}  clip Computed property value of clip\n * @return {Boolean}\n */\nfunction isClipped(clip) {\n\t'use strict';\n\n\tvar matches = clip.match(/rect\\s*\\(([0-9]+)px,?\\s*([0-9]+)px,?\\s*([0-9]+)px,?\\s*([0-9]+)px\\s*\\)/);\n\tif (matches && matches.length === 5) {\n\t\treturn matches[3] - matches[1] <= 0 && matches[2] - matches[4] <= 0;\n\t}\n\n\treturn false;\n\n}\n\n/**\n * Determine whether an element is visible\n *\n * @param {HTMLElement} el The HTMLElement\n * @param {Boolean} screenReader When provided, will evaluate visibility from the perspective of a screen reader\n * @return {Boolean} The element's visibilty status\n */\ndom.isVisible = function (el, screenReader, recursed) {\n\t'use strict';\n\tvar style,\n\t\tnodeName = el.nodeName,\n\t\tparent = el.parentNode;\n\n\t// 9 === Node.DOCUMENT\n\tif (el.nodeType === 9) {\n\t\treturn true;\n\t}\n\n\tstyle = window.getComputedStyle(el, null);\n\tif (style === null) {\n\t\treturn false;\n\t}\n\n\tif (style.getPropertyValue('display') === 'none' ||\n\n\t\tnodeName.toUpperCase() === 'STYLE' || nodeName.toUpperCase() === 'SCRIPT' ||\n\n\t\t(!screenReader && (isClipped(style.getPropertyValue('clip')))) ||\n\n\t\t(!recursed &&\n\t\t\t// visibility is only accurate on the first element\n\t\t\t(style.getPropertyValue('visibility') === 'hidden' ||\n\t\t\t// position does not matter if it was already calculated\n\t\t\t!screenReader && dom.isOffscreen(el))) ||\n\n\t\t(screenReader && el.getAttribute('aria-hidden') === 'true')) {\n\n\t\treturn false;\n\t}\n\n\tif (parent) {\n\t\treturn dom.isVisible(parent, screenReader, true);\n\t}\n\n\treturn false;\n\n};\n\n/*global dom */\n/*jshint maxcomplexity: 20 */\n\n/**\n * Check if an element is an inherently visual element\n * @param  {object}  candidate The node to check\n * @return {Boolean}\n */\ndom.isVisualContent = function (candidate) {\n\t'use strict';\n\tswitch (candidate.tagName.toUpperCase()) {\n\t\tcase 'IMG':\n\t\tcase 'IFRAME':\n\t\tcase 'OBJECT':\n\t\tcase 'VIDEO':\n\t\tcase 'AUDIO':\n\t\tcase 'CANVAS':\n\t\tcase 'SVG':\n\t\tcase 'MATH':\n\t\tcase 'BUTTON':\n\t\tcase 'SELECT':\n\t\tcase 'TEXTAREA':\n\t\tcase 'KEYGEN':\n\t\tcase 'PROGRESS':\n\t\tcase 'METER':\n\t\t\treturn true;\n\t\tcase 'INPUT':\n\t\t\treturn candidate.type !== 'hidden';\n\t\tdefault:\n\t\t\treturn false;\n\t}\n\n};\n\n/* global dom */\n/* jshint maxcomplexity: 11 */\n\n/**\n * Checks whether a parent element visually contains its child, either directly or via scrolling.\n * Assumes that |parent| is an ancestor of |node|.\n * @param {Element} node\n * @param {Element} parent\n * @return {boolean} True if node is visually contained within parent\n */\ndom.visuallyContains = function (node, parent) {\n\tvar rect = node.getBoundingClientRect();\n\tvar parentRect = parent.getBoundingClientRect();\n\tvar parentTop = parentRect.top;\n\tvar parentLeft = parentRect.left;\n\tvar parentScrollArea = {\n\t\ttop: parentTop - parent.scrollTop,\n\t\tbottom: parentTop - parent.scrollTop + parent.scrollHeight,\n\t\tleft: parentLeft - parent.scrollLeft,\n\t\tright: parentLeft - parent.scrollLeft + parent.scrollWidth\n\t};\n\n\t//In theory, we should just be able to look at the scroll area as a superset of the parentRect,\n\t//but that's not true in Firefox\n\tif ((rect.left < parentScrollArea.left && rect.left < parentRect.left) ||\n\t\t(rect.top < parentScrollArea.top && rect.top < parentRect.top) ||\n\t\t(rect.right > parentScrollArea.right && rect.right > parentRect.right) ||\n\t\t(rect.bottom > parentScrollArea.bottom && rect.bottom > parentRect.bottom)) {\n\t\treturn false;\n\t}\n\n\tvar style = window.getComputedStyle(parent);\n\n\tif (rect.right > parentRect.right || rect.bottom > parentRect.bottom) {\n\t\treturn (style.overflow === 'scroll' || style.overflow === 'auto' ||\n\t\t\t\tstyle.overflow === 'hidden' || parent instanceof HTMLBodyElement ||\n\t\t\t\tparent instanceof HTMLHtmlElement);\n\t}\n\n\treturn true;\n};\n\n/* global dom */\n/* jshint maxcomplexity: 11 */\n\n/**\n * Checks whether a parent element visually overlaps a rectangle, either directly or via scrolling.\n * @param {DOMRect} rect\n * @param {Element} parent\n * @return {boolean} True if rect is visually contained within parent\n */\ndom.visuallyOverlaps = function (rect, parent) {\n\tvar parentRect = parent.getBoundingClientRect();\n\tvar parentTop = parentRect.top;\n\tvar parentLeft = parentRect.left;\n\tvar parentScrollArea = {\n\t\ttop: parentTop - parent.scrollTop,\n\t\tbottom: parentTop - parent.scrollTop + parent.scrollHeight,\n\t\tleft: parentLeft - parent.scrollLeft,\n\t\tright: parentLeft - parent.scrollLeft + parent.scrollWidth\n\t};\n\n\t//In theory, we should just be able to look at the scroll area as a superset of the parentRect,\n\t//but that's not true in Firefox\n\tif ((rect.left > parentScrollArea.right && rect.left > parentRect.right) ||\n\t\t(rect.top > parentScrollArea.bottom && rect.top > parentRect.bottom) ||\n\t\t(rect.right < parentScrollArea.left && rect.right < parentRect.left) ||\n\t\t(rect.bottom < parentScrollArea.top && rect.bottom < parentRect.top)) {\n\t\treturn false;\n\t}\n\n\tvar style = window.getComputedStyle(parent);\n\n\tif (rect.left > parentRect.right || rect.top > parentRect.bottom) {\n\t\treturn (style.overflow === 'scroll' || style.overflow === 'auto' ||\n\t\t\t\tparent instanceof HTMLBodyElement ||\n\t\t\t\tparent instanceof HTMLHtmlElement);\n\t}\n\n\treturn true;\n};\n\n/*global table, dom */\n\n/**\n * Get the x, y coordinates of a table cell; normalized for rowspan and colspan\n * @param  {HTMLTableCelLElement} cell The table cell of which to get the position\n * @return {Object}      Object with `x` and `y` properties of the coordinates\n */\ntable.getCellPosition = function (cell) {\n\n\tvar tbl = table.toArray(dom.findUp(cell, 'table')),\n\t\tindex;\n\n\tfor (var rowIndex = 0; rowIndex < tbl.length; rowIndex++) {\n\t\tif (tbl[rowIndex]) {\n\t\t\tindex = tbl[rowIndex].indexOf(cell);\n\t\t\tif (index !== -1) {\n\t\t\t\treturn {\n\t\t\t\t\tx: index,\n\t\t\t\t\ty: rowIndex\n\t\t\t\t};\n\t\t\t}\n\t\t}\n\t}\n\n};\n/*global table */\n\n/**\n * Get any associated table headers for a `HTMLTableCellElement`\n * @param  {HTMLTableCellElement} cell The cell of which to get headers\n * @return {Array}      Array of headers associated to the table cell\n */\ntable.getHeaders = function (cell) {\n\n\tif (cell.getAttribute('headers')) {\n\t\treturn commons.dom.idrefs(cell, 'headers');\n\t}\n\n\tvar headers = [], currentCell,\n\t\ttbl = commons.table.toArray(commons.dom.findUp(cell, 'table')),\n\t\tposition = commons.table.getCellPosition(cell);\n\n\t//\n\tfor (var x = position.x - 1; x >= 0; x--) {\n\t\tcurrentCell = tbl[position.y][x];\n\n\t\tif (commons.table.isRowHeader(currentCell)) {\n\t\t\theaders.unshift(currentCell);\n\t\t}\n\t}\n\n\tfor (var y = position.y - 1; y >= 0; y--) {\n\t\tcurrentCell = tbl[y][position.x];\n\n\t\tif (currentCell && commons.table.isColumnHeader(currentCell)) {\n\t\t\theaders.unshift(currentCell);\n\t\t}\n\t}\n\n\treturn headers;\n\n};\n/*global table, dom */\n\n/**\n * Determine if a `HTMLTableCellElement` is a column header\n * @param  {HTMLTableCellElement}  node The table cell to test\n * @return {Boolean}\n */\ntable.isColumnHeader = function (node) {\n\n\tvar scope = node.getAttribute('scope');\n\tif (scope === 'col') {\n\t\treturn true;\n\t} else if (scope || node.nodeName.toUpperCase() !== 'TH') {\n\t\treturn false;\n\t}\n\n\tvar currentCell,\n\t\tposition = table.getCellPosition(node),\n\t\ttbl = table.toArray(dom.findUp(node, 'table')),\n\t\tcells = tbl[position.y];\n\n\tfor (var cellIndex = 0, cellLength = cells.length; cellIndex < cellLength; cellIndex++) {\n\t\tcurrentCell = cells[cellIndex];\n\t\tif (currentCell !== node) {\n\t\t\tif (table.isDataCell(currentCell)) {\n\t\t\t\treturn false;\n\t\t\t}\n\t\t}\n\t}\n\n\treturn true;\n\n};\n/*global table */\n\n/**\n * Determine if a `HTMLTableCellElement` is a data cell\n * @param  {HTMLTableCellElement}  node The table cell to test\n * @return {Boolean}\n */\ntable.isDataCell = function (cell) {\n\t// @see http://www.whatwg.org/specs/web-apps/current-work/multipage/tables.html#empty-cell\n\tif (!cell.children.length && !cell.textContent.trim()) {\n\t\treturn false;\n\t}\n\treturn cell.nodeName.toUpperCase() === 'TD';\n};\n/*global table, dom */\n/*jshint maxstatements: 65, maxcomplexity: 37 */\n\n/**\n * Determines whether a table is a data table\n * @param  {HTMLTableElement}  node The table to test\n * @return {Boolean}\n * @see http://asurkov.blogspot.co.uk/2011/10/data-vs-layout-table.html\n */\ntable.isDataTable = function (node) {\n\n\tvar role = node.getAttribute('role');\n\n\t// The element is not focusable and has role=presentation\n\tif ((role === 'presentation' || role === 'none') && !dom.isFocusable(node)) {\n\t\treturn false;\n\t}\n\n\t// Table inside editable area is data table always since the table structure is crucial for table editing\n\tif (node.getAttribute('contenteditable') === 'true' || dom.findUp(node, '[contenteditable=\"true\"]')) {\n\t\treturn true;\n\t}\n\n\t// Table having ARIA table related role is data table\n\tif (role === 'grid' || role === 'treegrid' || role === 'table') {\n\t\treturn true;\n\t}\n\n\t// Table having ARIA landmark role is data table\n\tif (commons.aria.getRoleType(role) === 'landmark') {\n\t\treturn true;\n\t}\n\n\t// Table having datatable=\"0\" attribute is layout table\n\tif (node.getAttribute('datatable') === '0') {\n\t\treturn false;\n\t}\n\n\t// Table having summary attribute is data table\n\tif (node.getAttribute('summary')) {\n\t\treturn true;\n\n\t}\n\n\t// Table having legitimate data table structures is data table\n\tif (node.tHead || node.tFoot || node.caption) {\n\t\treturn true;\n\t}\n\t// colgroup / col - colgroup is magically generated\n\tfor (var childIndex = 0, childLength = node.children.length; childIndex < childLength; childIndex++) {\n\t\tif (node.children[childIndex].nodeName.toUpperCase() === 'COLGROUP') {\n\t\t\treturn true;\n\t\t}\n\t}\n\n\tvar cells = 0;\n\tvar rowLength = node.rows.length;\n\tvar row, cell;\n\tvar hasBorder = false;\n\tfor (var rowIndex = 0; rowIndex < rowLength; rowIndex++) {\n\t\trow = node.rows[rowIndex];\n\t\tfor (var cellIndex = 0, cellLength = row.cells.length; cellIndex < cellLength; cellIndex++) {\n\t\t\tcell = row.cells[cellIndex];\n\t\t\tif (!hasBorder && (cell.offsetWidth !== cell.clientWidth || cell.offsetHeight !== cell.clientHeight)) {\n\t\t\t\thasBorder = true;\n\t\t\t}\n\t\t\tif (cell.getAttribute('scope') || cell.getAttribute('headers') || cell.getAttribute('abbr')) {\n\t\t\t\treturn true;\n\t\t\t}\n\t\t\tif (cell.nodeName.toUpperCase() === 'TH') {\n\t\t\t\treturn true;\n\t\t\t}\n\t\t\t// abbr element as a single child element of table cell\n\t\t\tif (cell.children.length === 1 && cell.children[0].nodeName.toUpperCase() === 'ABBR') {\n\t\t\t\treturn true;\n\t\t\t}\n\t\t\tcells++;\n\t\t}\n\t}\n\n\t// Table having nested table is layout table\n\tif (node.getElementsByTagName('table').length) {\n\t\treturn false;\n\t}\n\n\t// Table having only one row or column is layout table (row)\n\tif (rowLength < 2) {\n\t\treturn false;\n\t}\n\n\t// Table having only one row or column is layout table (column)\n\tvar sampleRow = node.rows[Math.ceil(rowLength / 2)];\n\tif (sampleRow.cells.length === 1 && sampleRow.cells[0].colSpan === 1) {\n\t\treturn false;\n\t}\n\n\t// Table having many columns (>= 5) is data table\n\tif (sampleRow.cells.length >= 5) {\n\t\treturn true;\n\t}\n\n\t// Table having borders around cells is data table\n\tif (hasBorder) {\n\t\treturn true;\n\t}\n\n\t// Table having differently colored rows is data table\n\tvar bgColor, bgImage;\n\tfor (rowIndex = 0; rowIndex < rowLength; rowIndex++) {\n\t\trow = node.rows[rowIndex];\n\t\tif (bgColor && bgColor !== window.getComputedStyle(row).getPropertyValue('background-color')) {\n\t\t\treturn true;\n\t\t} else {\n\t\t\tbgColor = window.getComputedStyle(row).getPropertyValue('background-color');\n\t\t}\n\t\tif (bgImage && bgImage !== window.getComputedStyle(row).getPropertyValue('background-image')) {\n\t\t\treturn true;\n\t\t} else {\n\t\t\tbgImage = window.getComputedStyle(row).getPropertyValue('background-image');\n\t\t}\n\n\t}\n\n\t// Table having many rows (>= 20) is data table\n\tif (rowLength >= 20) {\n\t\treturn true;\n\t}\n\n\t// Wide table (more than 95% of the document width) is layout table\n\tif (dom.getElementCoordinates(node).width > dom.getViewportSize(window).width * 0.95) {\n\t\treturn false;\n\t}\n\n\t// Table having small amount of cells (<= 10) is layout table\n\tif (cells < 10) {\n\t\treturn false;\n\t}\n\n\t// Table containing embed, object, applet of iframe elements (typical advertisements elements) is layout table\n\tif (node.querySelector('object, embed, iframe, applet')) {\n\t\treturn false;\n\t}\n\n\t// Otherwise it's data table\n\treturn true;\n};\n\n/*global table, utils */\n\n/**\n * Determine if a `HTMLTableCellElement` is a header\n * @param  {HTMLTableCellElement}  node The table cell to test\n * @return {Boolean}\n */\ntable.isHeader = function (cell) {\n\tif (table.isColumnHeader(cell) || table.isRowHeader(cell)) {\n\t\treturn true;\n\t}\n\n\tif (cell.id) {\n\t\treturn !!document.querySelector('[headers~=\"' + utils.escapeSelector(cell.id) + '\"]');\n\t}\n\n\treturn false;\n};\n\n/*global table, dom */\n\n/**\n * Determine if a `HTMLTableCellElement` is a row header\n * @param  {HTMLTableCellElement}  node The table cell to test\n * @return {Boolean}\n */\ntable.isRowHeader = function (node) {\n\n\n\tvar scope = node.getAttribute('scope');\n\tif (scope === 'row') {\n\t\treturn true;\n\t} else if (scope || node.nodeName.toUpperCase() !== 'TH') {\n\t\treturn false;\n\t}\n\n\tif (table.isColumnHeader(node)) {\n\t\treturn false;\n\t}\n\n\tvar currentCell,\n\t\tposition = table.getCellPosition(node),\n\t\ttbl = table.toArray(dom.findUp(node, 'table'));\n\n\tfor (var rowIndex = 0, rowLength = tbl.length; rowIndex < rowLength; rowIndex++) {\n\t\tcurrentCell = tbl[rowIndex][position.x];\n\t\tif (currentCell !== node) {\n\t\t\tif (table.isDataCell(currentCell)) {\n\t\t\t\treturn false;\n\t\t\t}\n\t\t}\n\t}\n\n\treturn true;\n\n};\n/*global table */\n\n/**\n * Converts a table to an Array, normalized for row and column spans\n * @param  {HTMLTableElement} node The table to convert\n * @return {Array}      Array of rows and cells\n */\ntable.toArray = function (node) {\n\tvar table = [];\n\tvar rows = node.rows;\n\tfor (var i = 0, rowLength = rows.length; i < rowLength; i++) {\n\t\tvar cells = rows[i].cells;\n\t\ttable[i] = table[i] || [];\n\n\t\tvar columnIndex = 0;\n\n\t\tfor (var j = 0, cellLength = cells.length; j < cellLength; j++) {\n\t\t\tfor (var colSpan = 0; colSpan < cells[j].colSpan; colSpan++) {\n\t\t\t\tfor (var rowSpan = 0; rowSpan < cells[j].rowSpan; rowSpan++) {\n\t\t\t\t\ttable[i + rowSpan] = table[i + rowSpan] || [];\n\t\t\t\t\twhile (table[i + rowSpan][columnIndex]) {\n\t\t\t\t\t\tcolumnIndex++;\n\t\t\t\t\t}\n\t\t\t\t\ttable[i + rowSpan][columnIndex] = cells[j];\n\t\t\t\t}\n\t\t\t\tcolumnIndex++;\n\t\t\t}\n\t\t}\n\t}\n\n\treturn table;\n};\n\n/*global text, dom, aria, utils */\n/*jshint maxstatements: 25, maxcomplexity: 19 */\n\nvar defaultButtonValues = {\n\tsubmit: 'Submit',\n\treset: 'Reset'\n};\n\nvar inputTypes = ['text', 'search', 'tel', 'url', 'email', 'date', 'time', 'number', 'range', 'color'];\nvar phrasingElements = ['a', 'em', 'strong', 'small', 'mark', 'abbr', 'dfn', 'i', 'b', 's', 'u', 'code',\n\t'var', 'samp', 'kbd', 'sup', 'sub', 'q', 'cite', 'span', 'bdo', 'bdi', 'br', 'wbr', 'ins', 'del', 'img',\n\t'embed', 'object', 'iframe', 'map', 'area', 'script', 'noscript', 'ruby', 'video', 'audio', 'input',\n\t'textarea', 'select', 'button', 'label', 'output', 'datalist', 'keygen', 'progress', 'command',\n\t'canvas', 'time', 'meter'];\n\n/**\n * Find a non-ARIA label for an element\n *\n * @param {HTMLElement} element The HTMLElement\n * @return {HTMLElement} The label element, or null if none is found\n */\nfunction findLabel(element) {\n\tvar ref = null;\n\tif (element.id) {\n\t\tref = document.querySelector('label[for=\"' + utils.escapeSelector(element.id) + '\"]');\n\t\tif (ref) {\n\t\t\treturn ref;\n\t\t}\n\t}\n\tref = dom.findUp(element, 'label');\n\treturn ref;\n}\n\nfunction isButton(element) {\n\treturn ['button', 'reset', 'submit'].indexOf(element.type) !== -1;\n}\n\nfunction isInput(element) {\n\tvar nodeName = element.nodeName.toUpperCase();\n\treturn (nodeName === 'TEXTAREA' || nodeName === 'SELECT') ||\n\t\t(nodeName === 'INPUT' && element.type !== 'hidden');\n}\n\nfunction shouldCheckSubtree(element) {\n\treturn ['BUTTON', 'SUMMARY', 'A'].indexOf(element.nodeName.toUpperCase()) !== -1;\n}\n\nfunction shouldNeverCheckSubtree(element) {\n\treturn ['TABLE', 'FIGURE'].indexOf(element.nodeName.toUpperCase()) !== -1;\n}\n\n/**\n * Calculate value of a form element when treated as a value\n *\n * @param {HTMLElement} element The HTMLElement\n * @return {string} The calculated value\n */\nfunction formValueText(element) {\n\tvar nodeName = element.nodeName.toUpperCase();\n\tif (nodeName === 'INPUT') {\n\t\tif (!element.hasAttribute('type') || (inputTypes.indexOf(element.getAttribute('type')) !== -1) && element.value) {\n\t\t\treturn element.value;\n\t\t}\n\t\treturn '';\n\t}\n\n\tif (nodeName === 'SELECT') {\n\t\tvar opts = element.options;\n\t\tif (opts && opts.length) {\n\t\t\tvar returnText = '';\n\t\t\tfor (var i = 0; i < opts.length; i++) {\n\t\t\t\tif (opts[i].selected) {\n\t\t\t\t\treturnText += ' ' + opts[i].text;\n\t\t\t\t}\n\t\t\t}\n\t\t\treturn text.sanitize(returnText);\n\t\t}\n\t\treturn '';\n\t}\n\n\tif (nodeName === 'TEXTAREA' && element.value) {\n\t\treturn element.value;\n\t}\n\treturn '';\n}\n\nfunction checkDescendant(element, nodeName) {\n\tvar candidate = element.querySelector(nodeName);\n\tif (candidate) {\n\t\treturn text.accessibleText(candidate);\n\t}\n\n\treturn '';\n}\n\n\n/**\n * Determine whether an element can be an embedded control\n *\n * @param {HTMLElement} element The HTMLElement\n * @return {boolean} True if embedded control\n */\nfunction isEmbeddedControl(e) {\n\tif (!e) {\n\t\treturn false;\n\t}\n\tswitch (e.nodeName.toUpperCase()) {\n\t\tcase 'SELECT':\n\t\tcase 'TEXTAREA':\n\t\t\treturn true;\n\t\tcase 'INPUT':\n\t\t\treturn !e.hasAttribute('type') || (inputTypes.indexOf(e.getAttribute('type')) !== -1);\n\t\tdefault:\n\t\t\treturn false;\n\t}\n}\n\nfunction shouldCheckAlt(element) {\n\tvar nodeName = element.nodeName.toUpperCase();\n\treturn (nodeName === 'INPUT' && element.type === 'image') ||\n\t\t['IMG', 'APPLET', 'AREA'].indexOf(nodeName) !== -1;\n}\n\nfunction nonEmptyText(t) {\n\treturn !!text.sanitize(t);\n}\n\n/**\n * Determine the accessible text of an element, using logic from ARIA:\n * http://www.w3.org/TR/html-aam-1.0/\n * http://www.w3.org/TR/wai-aria/roles#textalternativecomputation\n *\n * @param {HTMLElement} element The HTMLElement\n * @return {string}\n */\ntext.accessibleText = function(element) {\n\n\tfunction checkNative(element, inLabelledByContext, inControlContext) {\n\t\tvar returnText = '',\n\t\t\tnodeName = element.nodeName.toUpperCase();\n\t\tif (shouldCheckSubtree(element)) {\n\t\t\treturnText = getInnerText(element, false, false) || '';\n\t\t\tif (nonEmptyText(returnText)) {\n\t\t\t\treturn returnText;\n\t\t\t}\n\t\t}\n\t\tif (nodeName === 'FIGURE') {\n\t\t\treturnText = checkDescendant(element, 'figcaption');\n\n\t\t\tif (nonEmptyText(returnText)) {\n\t\t\t\treturn returnText;\n\t\t\t}\n\t\t}\n\n\t\tif (nodeName === 'TABLE') {\n\t\t\treturnText = checkDescendant(element, 'caption');\n\n\t\t\tif (nonEmptyText(returnText)) {\n\t\t\t\treturn returnText;\n\t\t\t}\n\n\t\t\treturnText = element.getAttribute('title') || element.getAttribute('summary') || '';\n\n\t\t\tif (nonEmptyText(returnText)) {\n\t\t\t\treturn returnText;\n\t\t\t}\n\t\t}\n\n\t\tif (shouldCheckAlt(element)) {\n\t\t\treturn element.getAttribute('alt') || '';\n\t\t}\n\n\t\tif (isInput(element) && !inControlContext) {\n\t\t\tif (isButton(element)) {\n\t\t\t\treturn element.value || element.title || defaultButtonValues[element.type] || '';\n\t\t\t}\n\n\t\t\tvar labelElement = findLabel(element);\n\t\t\tif (labelElement) {\n\t\t\t\treturn accessibleNameComputation(labelElement, inLabelledByContext, true);\n\t\t\t}\n\t\t}\n\n\t\treturn '';\n\t}\n\n\tfunction checkARIA(element, inLabelledByContext, inControlContext) {\n\n\t\tif (!inLabelledByContext && element.hasAttribute('aria-labelledby')) {\n\t\t\treturn text.sanitize(dom.idrefs(element, 'aria-labelledby').map(function(l) {\n\t\t\t\tif (element === l) {\n\t\t\t\t\tencounteredNodes.pop();\n\t\t\t\t} //let element be encountered twice\n\t\t\t\treturn accessibleNameComputation(l, true, element !== l);\n\t\t\t}).join(' '));\n\t\t}\n\n\t\tif (!(inControlContext && isEmbeddedControl(element)) && element.hasAttribute('aria-label')) {\n\t\t\treturn text.sanitize(element.getAttribute('aria-label'));\n\t\t}\n\n\t\treturn '';\n\t}\n\n\tfunction getInnerText(element, inLabelledByContext, inControlContext) {\n\n\t\tvar nodes = element.childNodes;\n\t\tvar returnText = '';\n\t\tvar node;\n\n\t\tfor (var i = 0; i < nodes.length; i++) {\n\t\t\tnode = nodes[i];\n\t\t\tif (node.nodeType === 3) {\n\t\t\t\treturnText += node.textContent;\n\t\t\t} else if (node.nodeType === 1) {\n\t\t\t\tif (phrasingElements.indexOf(node.nodeName.toLowerCase()) === -1) {\n\t\t\t\t\treturnText += ' ';\n\t\t\t\t}\n\t\t\t\treturnText += accessibleNameComputation(nodes[i], inLabelledByContext, inControlContext);\n\t\t\t}\n\t\t}\n\n\t\treturn returnText;\n\n\t}\n\n\n\tvar encounteredNodes = [];\n\n\t/**\n\t * Determine the accessible text of an element, using logic from ARIA:\n\t * http://www.w3.org/TR/accname-aam-1.1/#mapping_additional_nd_name\n\t *\n\t * @param {HTMLElement} element The HTMLElement\n\t * @param {Boolean} inLabelledByContext True when in the context of resolving a labelledBy\n\t * @param {Boolean} inControlContext True when in the context of textifying a widget\n\t * @return {string}\n\t */\n\tfunction accessibleNameComputation(element, inLabelledByContext, inControlContext) {\n\t\t'use strict';\n\n\t\tvar returnText = '';\n\n\t\t//Step 2a\n\t\tif (element === null || !dom.isVisible(element, true) || (encounteredNodes.indexOf(element) !== -1)) {\n\t\t\treturn '';\n\t\t}\n\t\tencounteredNodes.push(element);\n\t\tvar role = element.getAttribute('role');\n\n\t\t//Step 2b & 2c\n\t\treturnText += checkARIA(element, inLabelledByContext, inControlContext);\n\t\tif (nonEmptyText(returnText)) {\n\t\t\treturn returnText;\n\t\t}\n\n\t\t//Step 2d - native attribute or elements\n\t\treturnText = checkNative(element, inLabelledByContext, inControlContext);\n\t\tif (nonEmptyText(returnText)) {\n\t\t\treturn returnText;\n\t\t}\n\n\t\t//Step 2e\n\t\tif (inControlContext) {\n\t\t\treturnText += formValueText(element);\n\t\t\tif (nonEmptyText(returnText)) {\n\t\t\t\treturn returnText;\n\t\t\t}\n\t\t}\n\n\t\t//Step 2f\n\t\tif (!shouldNeverCheckSubtree(element) && (!role || aria.getRolesWithNameFromContents().indexOf(role) !== -1)) {\n\n\t\t\treturnText = getInnerText(element, inLabelledByContext, inControlContext);\n\n\t\t\tif (nonEmptyText(returnText)) {\n\t\t\t\treturn returnText;\n\t\t\t}\n\t\t}\n\n\t\t//Step 2g - if text node, return value (handled in getInnerText)\n\n\t\t//Step 2h\n\t\tif (element.hasAttribute('title')) {\n\t\t\treturn element.getAttribute('title');\n\t\t}\n\n\t\treturn '';\n\t}\n\n\treturn text.sanitize(accessibleNameComputation(element));\n};\n\n/*global text, dom, utils, aria */\n/**\n * Gets the visible text of a label for a given input\n * @see http://www.w3.org/WAI/PF/aria/roles#namecalculation\n * @param  {HTMLElement} node The input to test\n * @return {Mixed}      String of visible text, or `null` if no label is found\n */\ntext.label = function (node) {\n\tvar ref, candidate;\n\n\tcandidate = aria.label(node);\n\tif (candidate) {\n\t\treturn candidate;\n\t}\n\n\t// explicit label\n\tif (node.id) {\n\t\tref = document.querySelector('label[for=\"' + utils.escapeSelector(node.id) + '\"]');\n\t\tcandidate = ref && text.visible(ref, true);\n\t\tif (candidate) {\n\t\t\treturn candidate;\n\t\t}\n\t}\n\n\tref = dom.findUp(node, 'label');\n\tcandidate = ref && text.visible(ref, true);\n\tif (candidate) {\n\t\treturn candidate;\n\t}\n\n\treturn null;\n};\n\n/*global text */\ntext.sanitize = function (str) {\n\t'use strict';\n\treturn str\n\t\t.replace(/\\r\\n/g, '\\n')\n\t\t.replace(/\\u00A0/g, ' ')\n\t\t.replace(/[\\s]{2,}/g, ' ')\n\t\t.trim();\n};\n\n/*global text, dom */\n\ntext.visible = function (element, screenReader, noRecursing) {\n\t'use strict';\n\n\tvar index, child, nodeValue,\n\t\tchildNodes = element.childNodes,\n\t\tlength = childNodes.length,\n\t\tresult = '';\n\n\tfor (index = 0; index < length; index++) {\n\t\tchild = childNodes[index];\n\n\t\tif (child.nodeType === 3) {\n\t\t\tnodeValue = child.nodeValue;\n\t\t\tif (nodeValue && dom.isVisible(element, screenReader)) {\n\t\t\t\tresult += child.nodeValue;\n\t\t\t}\n\t\t} else if (!noRecursing) {\n\t\t\tresult += text.visible(child, screenReader);\n\t\t}\n\t}\n\n\treturn text.sanitize(result);\n};\n\n/*global utils */\nutils.toArray = function (thing) {\n\t'use strict';\n\treturn Array.prototype.slice.call(thing);\n};\n/*global utils */\n\n\nutils.tokenList = function (str) {\n\t'use strict';\n\n\treturn str.trim().replace(/\\s{2,}/g, ' ').split(' ');\n};\n\treturn commons;\n}())\n});\n\n\taxe.version = '1.1.1';\n\tif (typeof define === \"function\" && define.amd) this.axe = axe, define(axe); else if (typeof module === \"object\" && module.exports) module.exports = axe; else window.axe = axe;\n}(window, window.document));\n";