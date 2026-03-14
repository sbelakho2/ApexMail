# @apexmail/bot-detector-native

Native Node.js addon for bot and crawler User-Agent detection, built with [napi-rs](https://napi.rs).

## Overview

Uses an Aho-Corasick automaton pre-loaded with 70+ known bot patterns (search engines, social crawlers, email gateways, automation tools, security scanners) for high-throughput detection with zero regex overhead.

## Usage

```js
import { detectBot, detectBotsBatch } from '@apexmail/bot-detector-native';

const result = detectBot('Googlebot/2.1 (+http://www.google.com/bot.html)');
// { isBot: true, category: 'search-engine', confidence: 1.0, matchedPattern: 'googlebot' }

const batch = detectBotsBatch(userAgents);
// { results: [...], botCount: 12, humanCount: 88 }
```

## API

| Function | Description |
|---|---|
| `detectBot(ua)` | Classify a single User-Agent string |
| `detectBotsBatch(uas)` | Classify an array of User-Agent strings |
| `isKnownBotPattern(p)` | Check if a pattern is in the built-in set |
| `getBotPatterns()` | Return all patterns grouped by category |
| `setCustomPatterns(p, replace)` | Add or replace runtime patterns |
| `patternCount()` | Number of loaded patterns |
| `getCategories()` | List all pattern categories |
| `warmup()` | Pre-warm the automaton (call at startup) |

## Build

Requires Rust toolchain. The napi-rs build step runs automatically via `build.rs`.

```sh
pnpm install
```

## Internal

This is an internal package — not published to npm.
