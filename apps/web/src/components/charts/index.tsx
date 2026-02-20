'use client';

import * as React from 'react';
import {
 LineChart,
 Line,
 BarChart,
 Bar,
 AreaChart,
 Area,
 PieChart,
 Pie,
 Cell,
 XAxis,
 YAxis,
 CartesianGrid,
 Tooltip,
 Legend,
 ResponsiveContainer,
 type TooltipProps,
} from 'recharts';
import { cn } from '@/lib/utils';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';

// Color palette for charts
const CHART_COLORS = {
  primary: 'rgb(var(--primary))',
  secondary: 'rgb(var(--secondary))',
  success: 'rgb(var(--success))',
  warning: 'rgb(var(--warning))',
  error: 'rgb(var(--error))',
  muted: 'rgb(var(--muted))',
  accent: 'rgb(var(--accent))',
} as const;

const COLOR_ARRAY = [
  '#2563eb', // brand-500 (Primary Blue)
  '#64748b', // surface-500 (Gray)
  '#16a34a', // success (Green)
  '#d97706', // warning (Amber)
  '#dc2626', // danger (Red)
  '#1742b4', // brand-700 (Dark Blue)
  '#0891b2', // info (Cyan)
  '#8b5cf6', // violet
];

// Custom Tooltip component
function CustomTooltip({
  active,
  payload,
  label,
  formatter,
}: TooltipProps<number, string> & { formatter?: (value: number) => string }) {
  if (!active || !payload?.length) return null;

  return (
    <div className="rounded-lg border border-border bg-card/95 backdrop-blur-xl p-4 shadow-xl">
      <p className="mb-2 text-[13px] font-bold text-foreground uppercase tracking-tight">{label}</p>
      {payload.map((entry, index) => (
        <p key={index} className="text-sm font-medium flex items-center gap-2" style={{ color: entry.color }}>
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
          <span>{entry.name}:</span>
          <span className="font-bold apex-metric-number text-foreground">
            {formatter ? formatter(entry.value as number) : entry.value}
          </span>
        </p>
      ))}
    </div>
  );
}

// Line Chart Component
interface LineChartData {
 [key: string]: string | number;
}

interface ApexLineChartProps {
 data: LineChartData[];
 xKey: string;
 lines: Array<{
 key: string;
 name: string;
 color?: string;
 strokeDasharray?: string;
 }>;
 title?: string;
 description?: string;
 height?: number;
 showGrid?: boolean;
 showLegend?: boolean;
 formatter?: (value: number) => string;
 className?: string;
}

export function ApexLineChart({
 data,
 xKey,
 lines,
 title,
 description,
 height = 300,
 showGrid = true,
 showLegend = true,
 formatter,
 className,
}: ApexLineChartProps) {
 return (
 <Card className={cn(className)}>
 {(title || description) && (
 <CardHeader>
 {title && <CardTitle>{title}</CardTitle>}
 {description && <CardDescription>{description}</CardDescription>}
 </CardHeader>
 )}
 <CardContent>
 <ResponsiveContainer width="100%" height={height}>
 <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
 {showGrid && <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />}
 <XAxis
 dataKey={xKey}
 tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
 tickLine={{ stroke: 'hsl(var(--border))' }}
 axisLine={{ stroke: 'hsl(var(--border))' }}
 />
 <YAxis
 tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
 tickLine={{ stroke: 'hsl(var(--border))' }}
 axisLine={{ stroke: 'hsl(var(--border))' }}
 tickFormatter={formatter}
 />
 <Tooltip content={<CustomTooltip formatter={formatter} />} />
 {showLegend && <Legend />}
 {lines.map((line, index) => (
 <Line
 key={line.key}
 type="monotone"
 dataKey={line.key}
 name={line.name}
 stroke={line.color || COLOR_ARRAY[index % COLOR_ARRAY.length]}
 strokeWidth={2}
 strokeDasharray={line.strokeDasharray}
 dot={{ fill: line.color || COLOR_ARRAY[index % COLOR_ARRAY.length], r: 4 }}
 activeDot={{ r: 6 }}
 />
 ))}
 </LineChart>
 </ResponsiveContainer>
 </CardContent>
 </Card>
 );
}

// Bar Chart Component
interface ApexBarChartProps {
 data: LineChartData[];
 xKey: string;
 bars: Array<{
 key: string;
 name: string;
 color?: string;
 stackId?: string;
 }>;
 title?: string;
 description?: string;
 height?: number;
 showGrid?: boolean;
 showLegend?: boolean;
 layout?: 'vertical' | 'horizontal';
 formatter?: (value: number) => string;
 className?: string;
}

export function ApexBarChart({
 data,
 xKey,
 bars,
 title,
 description,
 height = 300,
 showGrid = true,
 showLegend = true,
 layout = 'horizontal',
 formatter,
 className,
}: ApexBarChartProps) {
 return (
 <Card className={cn(className)}>
 {(title || description) && (
 <CardHeader>
 {title && <CardTitle>{title}</CardTitle>}
 {description && <CardDescription>{description}</CardDescription>}
 </CardHeader>
 )}
 <CardContent>
 <ResponsiveContainer width="100%" height={height}>
 <BarChart
 data={data}
 layout={layout === 'vertical' ? 'vertical' : 'horizontal'}
 margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
 >
 {showGrid && <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />}
 {layout === 'vertical' ? (
 <>
 <XAxis type="number" tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} tickFormatter={formatter} />
 <YAxis type="category" dataKey={xKey} tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} />
 </>
 ) : (
 <>
 <XAxis dataKey={xKey} tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} />
 <YAxis tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }} tickFormatter={formatter} />
 </>
 )}
 <Tooltip content={<CustomTooltip formatter={formatter} />} />
 {showLegend && <Legend />}
 {bars.map((bar, index) => (
 <Bar
 key={bar.key}
 dataKey={bar.key}
 name={bar.name}
 fill={bar.color || COLOR_ARRAY[index % COLOR_ARRAY.length]}
 stackId={bar.stackId}
 radius={[4, 4, 0, 0]}
 />
 ))}
 </BarChart>
 </ResponsiveContainer>
 </CardContent>
 </Card>
 );
}

// Area Chart Component
interface ApexAreaChartProps {
 data: LineChartData[];
 xKey: string;
 areas: Array<{
 key: string;
 name: string;
 color?: string;
 stackId?: string;
 }>;
 title?: string;
 description?: string;
 height?: number;
 showGrid?: boolean;
 showLegend?: boolean;
 formatter?: (value: number) => string;
 className?: string;
}

export function ApexAreaChart({
 data,
 xKey,
 areas,
 title,
 description,
 height = 300,
 showGrid = true,
 showLegend = true,
 formatter,
 className,
}: ApexAreaChartProps) {
 return (
 <Card className={cn(className)}>
 {(title || description) && (
 <CardHeader>
 {title && <CardTitle>{title}</CardTitle>}
 {description && <CardDescription>{description}</CardDescription>}
 </CardHeader>
 )}
 <CardContent>
 <ResponsiveContainer width="100%" height={height}>
 <AreaChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
 {showGrid && <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />}
 <XAxis
 dataKey={xKey}
 tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
 />
 <YAxis
 tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 12 }}
 tickFormatter={formatter}
 />
 <Tooltip content={<CustomTooltip formatter={formatter} />} />
 {showLegend && <Legend />}
 {areas.map((area, index) => {
 const color = area.color || COLOR_ARRAY[index % COLOR_ARRAY.length];
 return (
 <Area
 key={area.key}
 type="monotone"
 dataKey={area.key}
 name={area.name}
 stroke={color}
 fill={color}
 fillOpacity={0.3}
 stackId={area.stackId}
 />
 );
 })}
 </AreaChart>
 </ResponsiveContainer>
 </CardContent>
 </Card>
 );
}

// Pie Chart Component
interface PieChartData {
 name: string;
 value: number;
 color?: string;
}

interface ApexPieChartProps {
 data: PieChartData[];
 title?: string;
 description?: string;
 height?: number;
 showLegend?: boolean;
 innerRadius?: number;
 outerRadius?: number;
 formatter?: (value: number) => string;
 className?: string;
}

export function ApexPieChart({
 data,
 title,
 description,
 height = 300,
 showLegend = true,
 innerRadius = 0,
 outerRadius = 80,
 formatter,
 className,
}: ApexPieChartProps) {
 const dataWithColors = data.map((item, index) => ({
 ...item,
 color: item.color || COLOR_ARRAY[index % COLOR_ARRAY.length],
 }));

 return (
 <Card className={cn(className)}>
 {(title || description) && (
 <CardHeader>
 {title && <CardTitle>{title}</CardTitle>}
 {description && <CardDescription>{description}</CardDescription>}
 </CardHeader>
 )}
 <CardContent>
 <ResponsiveContainer width="100%" height={height}>
 <PieChart>
 <Pie
 data={dataWithColors}
 cx="50%"
 cy="50%"
 innerRadius={innerRadius}
 outerRadius={outerRadius}
 paddingAngle={2}
 dataKey="value"
 label={({ name, percent }) =>
 `${name} (${(percent * 100).toFixed(0)}%)`
 }
 labelLine={{ stroke: 'hsl(var(--muted-foreground))' }}
 >
 {dataWithColors.map((entry, index) => (
 <Cell key={`cell-${index}`} fill={entry.color} />
 ))}
 </Pie>
 <Tooltip content={<CustomTooltip formatter={formatter} />} />
 {showLegend && <Legend />}
 </PieChart>
 </ResponsiveContainer>
 </CardContent>
 </Card>
 );
}

// Donut Chart (Pie with inner radius)
export function ApexDonutChart(props: ApexPieChartProps) {
 return <ApexPieChart {...props} innerRadius={60} outerRadius={80} />;
}

export { CHART_COLORS, COLOR_ARRAY };
