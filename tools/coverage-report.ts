#!/usr/bin/env tsx

/**
 * Test Coverage Report Aggregator
 * 
 * Aggregates test coverage reports from all packages and generates
 * a unified coverage report with thresholds enforcement.
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from 'fs';
import { join, relative } from 'path';

interface CoverageData {
  total: {
    lines: { total: number; covered: number; pct: number };
    statements: { total: number; covered: number; pct: number };
    functions: { total: number; covered: number; pct: number };
    branches: { total: number; covered: number; pct: number };
  };
  [file: string]: {
    lines: { total: number; covered: number; pct: number };
    statements: { total: number; covered: number; pct: number };
    functions: { total: number; covered: number; pct: number };
    branches: { total: number; covered: number; pct: number };
  };
}

interface CoverageSummary {
  lines: number;
  statements: number;
  functions: number;
  branches: number;
}

interface PackageCoverage {
  name: string;
  path: string;
  coverage: CoverageSummary;
  files: number;
  uncoveredFiles: string[];
}

// Coverage thresholds
const THRESHOLDS: CoverageSummary = {
  lines: 80,
  statements: 80,
  functions: 80,
  branches: 75,
};

// Colors for console output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bold: '\x1b[1m',
};

function getColor(value: number, threshold: number): string {
  if (value >= threshold) return colors.green;
  if (value >= threshold * 0.8) return colors.yellow;
  return colors.red;
}

function formatPercent(value: number, threshold: number): string {
  const color = getColor(value, threshold);
  const symbol = value >= threshold ? '✓' : '✗';
  return `${color}${value.toFixed(2)}%${colors.reset} ${symbol}`;
}

function findCoverageFiles(rootDir: string): string[] {
  const coverageFiles: string[] = [];
  const searchPaths = ['apps', 'packages'];

  for (const searchPath of searchPaths) {
    const basePath = join(rootDir, searchPath);
    if (!existsSync(basePath)) continue;

    const packages = readdirSync(basePath, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);

    for (const pkg of packages) {
      const coveragePath = join(basePath, pkg, 'reports', 'coverage', 'coverage-summary.json');
      if (existsSync(coveragePath)) {
        coverageFiles.push(coveragePath);
      }
      // Also check for coverage-final.json
      const coverageFinalPath = join(basePath, pkg, 'reports', 'coverage', 'coverage-final.json');
      if (existsSync(coverageFinalPath)) {
        coverageFiles.push(coverageFinalPath);
      }
    }
  }

  return coverageFiles;
}

function parseCoverage(filePath: string): PackageCoverage | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const data: CoverageData = JSON.parse(content);

    // Determine package name from path
    const pathParts = filePath.split('/');
    const appsIndex = pathParts.indexOf('apps');
    const packagesIndex = pathParts.indexOf('packages');
    const baseIndex = Math.max(appsIndex, packagesIndex);
    const packageName = baseIndex >= 0 ? pathParts[baseIndex + 1] : 'unknown';
    const packagePath = pathParts.slice(0, baseIndex + 2).join('/');

    if (!data.total) {
      // coverage-final.json format - aggregate ourselves
      let totalLines = 0, coveredLines = 0;
      let totalStatements = 0, coveredStatements = 0;
      let totalFunctions = 0, coveredFunctions = 0;
      let totalBranches = 0, coveredBranches = 0;
      const uncoveredFiles: string[] = [];

      for (const [file, fileData] of Object.entries(data)) {
        if (file === 'total') continue;
        const fd = fileData as any;
        
        // Count from statement/branch/function maps
        if (fd.s) {
          const statements = Object.values(fd.s) as number[];
          totalStatements += statements.length;
          coveredStatements += statements.filter((v: number) => v > 0).length;
        }
        if (fd.f) {
          const functions = Object.values(fd.f) as number[];
          totalFunctions += functions.length;
          coveredFunctions += functions.filter((v: number) => v > 0).length;
        }
        if (fd.b) {
          const branches = Object.values(fd.b).flat() as number[];
          totalBranches += branches.length;
          coveredBranches += branches.filter((v: number) => v > 0).length;
        }
      }

      return {
        name: packageName,
        path: packagePath,
        coverage: {
          lines: totalStatements > 0 ? (coveredStatements / totalStatements) * 100 : 0,
          statements: totalStatements > 0 ? (coveredStatements / totalStatements) * 100 : 0,
          functions: totalFunctions > 0 ? (coveredFunctions / totalFunctions) * 100 : 0,
          branches: totalBranches > 0 ? (coveredBranches / totalBranches) * 100 : 0,
        },
        files: Object.keys(data).length,
        uncoveredFiles,
      };
    }

    // coverage-summary.json format
    const uncoveredFiles: string[] = [];
    for (const [file, fileData] of Object.entries(data)) {
      if (file === 'total') continue;
      if (fileData.lines.pct < THRESHOLDS.lines) {
        uncoveredFiles.push(file);
      }
    }

    return {
      name: packageName,
      path: packagePath,
      coverage: {
        lines: data.total.lines.pct,
        statements: data.total.statements.pct,
        functions: data.total.functions.pct,
        branches: data.total.branches.pct,
      },
      files: Object.keys(data).length - 1, // Exclude 'total'
      uncoveredFiles,
    };
  } catch (error) {
    console.error(`Failed to parse coverage file: ${filePath}`, error);
    return null;
  }
}

function aggregateCoverage(packages: PackageCoverage[]): CoverageSummary {
  if (packages.length === 0) {
    return { lines: 0, statements: 0, functions: 0, branches: 0 };
  }

  const totals = packages.reduce(
    (acc, pkg) => ({
      lines: acc.lines + pkg.coverage.lines * pkg.files,
      statements: acc.statements + pkg.coverage.statements * pkg.files,
      functions: acc.functions + pkg.coverage.functions * pkg.files,
      branches: acc.branches + pkg.coverage.branches * pkg.files,
      totalFiles: acc.totalFiles + pkg.files,
    }),
    { lines: 0, statements: 0, functions: 0, branches: 0, totalFiles: 0 }
  );

  return {
    lines: totals.totalFiles > 0 ? totals.lines / totals.totalFiles : 0,
    statements: totals.totalFiles > 0 ? totals.statements / totals.totalFiles : 0,
    functions: totals.totalFiles > 0 ? totals.functions / totals.totalFiles : 0,
    branches: totals.totalFiles > 0 ? totals.branches / totals.totalFiles : 0,
  };
}

function generateReport(packages: PackageCoverage[], aggregate: CoverageSummary): string {
  const timestamp = new Date().toISOString();
  const passedThreshold = 
    aggregate.lines >= THRESHOLDS.lines &&
    aggregate.statements >= THRESHOLDS.statements &&
    aggregate.functions >= THRESHOLDS.functions &&
    aggregate.branches >= THRESHOLDS.branches;

  let report = `# ApexMail Test Coverage Report\n\n`;
  report += `**Generated:** ${timestamp}\n`;
  report += `**Status:** ${passedThreshold ? '✅ PASSING' : '❌ FAILING'}\n\n`;

  // Overall summary
  report += `## Overall Coverage\n\n`;
  report += `| Metric | Coverage | Threshold | Status |\n`;
  report += `|--------|----------|-----------|--------|\n`;
  report += `| Lines | ${aggregate.lines.toFixed(2)}% | ${THRESHOLDS.lines}% | ${aggregate.lines >= THRESHOLDS.lines ? '✅' : '❌'} |\n`;
  report += `| Statements | ${aggregate.statements.toFixed(2)}% | ${THRESHOLDS.statements}% | ${aggregate.statements >= THRESHOLDS.statements ? '✅' : '❌'} |\n`;
  report += `| Functions | ${aggregate.functions.toFixed(2)}% | ${THRESHOLDS.functions}% | ${aggregate.functions >= THRESHOLDS.functions ? '✅' : '❌'} |\n`;
  report += `| Branches | ${aggregate.branches.toFixed(2)}% | ${THRESHOLDS.branches}% | ${aggregate.branches >= THRESHOLDS.branches ? '✅' : '❌'} |\n\n`;

  // Package breakdown
  report += `## Package Coverage\n\n`;
  report += `| Package | Lines | Statements | Functions | Branches | Files |\n`;
  report += `|---------|-------|------------|-----------|----------|-------|\n`;

  const sortedPackages = [...packages].sort((a, b) => a.coverage.lines - b.coverage.lines);
  for (const pkg of sortedPackages) {
    const lineStatus = pkg.coverage.lines >= THRESHOLDS.lines ? '' : '⚠️';
    report += `| ${pkg.name} ${lineStatus} | ${pkg.coverage.lines.toFixed(1)}% | ${pkg.coverage.statements.toFixed(1)}% | ${pkg.coverage.functions.toFixed(1)}% | ${pkg.coverage.branches.toFixed(1)}% | ${pkg.files} |\n`;
  }

  // Low coverage files
  const allUncoveredFiles = packages.flatMap((pkg) =>
    pkg.uncoveredFiles.map((f) => ({ package: pkg.name, file: f }))
  );

  if (allUncoveredFiles.length > 0) {
    report += `\n## Files Below Threshold\n\n`;
    report += `The following files have line coverage below ${THRESHOLDS.lines}%:\n\n`;
    for (const { package: pkg, file } of allUncoveredFiles.slice(0, 20)) {
      report += `- \`${pkg}\`: ${file}\n`;
    }
    if (allUncoveredFiles.length > 20) {
      report += `\n... and ${allUncoveredFiles.length - 20} more files\n`;
    }
  }

  // Recommendations
  report += `\n## Recommendations\n\n`;
  const lowCoveragePackages = packages.filter((p) => p.coverage.lines < THRESHOLDS.lines);
  if (lowCoveragePackages.length > 0) {
    report += `### Packages Needing Attention\n\n`;
    for (const pkg of lowCoveragePackages) {
      const gap = THRESHOLDS.lines - pkg.coverage.lines;
      report += `- **${pkg.name}**: ${gap.toFixed(1)}% below threshold\n`;
    }
  } else {
    report += `All packages meet coverage thresholds! 🎉\n`;
  }

  return report;
}

function generateJsonReport(
  packages: PackageCoverage[],
  aggregate: CoverageSummary
): object {
  return {
    timestamp: new Date().toISOString(),
    thresholds: THRESHOLDS,
    aggregate,
    packages: packages.map((p) => ({
      name: p.name,
      path: p.path,
      coverage: p.coverage,
      files: p.files,
    })),
    passed:
      aggregate.lines >= THRESHOLDS.lines &&
      aggregate.statements >= THRESHOLDS.statements &&
      aggregate.functions >= THRESHOLDS.functions &&
      aggregate.branches >= THRESHOLDS.branches,
  };
}

async function main() {
  const rootDir = process.cwd();
  const outputDir = join(rootDir, 'reports', 'coverage');

  console.log(`${colors.bold}ApexMail Test Coverage Report${colors.reset}\n`);
  console.log('Scanning for coverage reports...\n');

  // Find all coverage files
  const coverageFiles = findCoverageFiles(rootDir);
  
  if (coverageFiles.length === 0) {
    console.log(`${colors.yellow}No coverage reports found.${colors.reset}`);
    console.log('Run "pnpm test:coverage" first to generate coverage data.\n');
    process.exit(0);
  }

  console.log(`Found ${coverageFiles.length} coverage reports.\n`);

  // Parse coverage data
  const packages: PackageCoverage[] = [];
  const seen = new Set<string>();

  for (const file of coverageFiles) {
    const coverage = parseCoverage(file);
    if (coverage && !seen.has(coverage.name)) {
      packages.push(coverage);
      seen.add(coverage.name);
    }
  }

  // Aggregate coverage
  const aggregate = aggregateCoverage(packages);

  // Print summary
  console.log(`${colors.bold}Overall Coverage:${colors.reset}\n`);
  console.log(`  Lines:      ${formatPercent(aggregate.lines, THRESHOLDS.lines)}`);
  console.log(`  Statements: ${formatPercent(aggregate.statements, THRESHOLDS.statements)}`);
  console.log(`  Functions:  ${formatPercent(aggregate.functions, THRESHOLDS.functions)}`);
  console.log(`  Branches:   ${formatPercent(aggregate.branches, THRESHOLDS.branches)}`);
  console.log();

  // Print package breakdown
  console.log(`${colors.bold}Package Coverage:${colors.reset}\n`);
  console.log('  Package'.padEnd(25) + 'Lines'.padEnd(10) + 'Status');
  console.log('  ' + '-'.repeat(45));

  const sortedPackages = [...packages].sort((a, b) => a.coverage.lines - b.coverage.lines);
  for (const pkg of sortedPackages) {
    const color = getColor(pkg.coverage.lines, THRESHOLDS.lines);
    const status = pkg.coverage.lines >= THRESHOLDS.lines ? '✓' : '✗';
    console.log(
      `  ${pkg.name.padEnd(23)} ${color}${pkg.coverage.lines.toFixed(1).padStart(6)}%${colors.reset}  ${status}`
    );
  }
  console.log();

  // Generate reports
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const markdownReport = generateReport(packages, aggregate);
  writeFileSync(join(outputDir, 'COVERAGE_REPORT.md'), markdownReport);
  console.log(`Markdown report: ${relative(rootDir, join(outputDir, 'COVERAGE_REPORT.md'))}`);

  const jsonReport = generateJsonReport(packages, aggregate);
  writeFileSync(join(outputDir, 'coverage-aggregate.json'), JSON.stringify(jsonReport, null, 2));
  console.log(`JSON report: ${relative(rootDir, join(outputDir, 'coverage-aggregate.json'))}`);
  console.log();

  // Exit with error if thresholds not met
  const passed =
    aggregate.lines >= THRESHOLDS.lines &&
    aggregate.statements >= THRESHOLDS.statements &&
    aggregate.functions >= THRESHOLDS.functions &&
    aggregate.branches >= THRESHOLDS.branches;

  if (!passed) {
    console.log(`${colors.red}${colors.bold}Coverage thresholds not met!${colors.reset}`);
    process.exit(1);
  } else {
    console.log(`${colors.green}${colors.bold}All coverage thresholds passed!${colors.reset}`);
  }
}

main().catch((error) => {
  console.error('Error generating coverage report:', error);
  process.exit(1);
});
