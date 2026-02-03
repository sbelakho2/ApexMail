'use client';

/**
 * ApexMail Chart Components
 * Pure SVG-based charts for Control Plane analytics
 * No external dependencies - printable and lightweight
 */

// Chart color palette following design system
export const CHART_COLORS = {
    primary: '#3b82f6',    // Blue
    success: '#10b981',    // Emerald
    warning: '#f59e0b',    // Amber
    danger: '#ef4444',     // Red
    info: '#0ea5e9',       // Sky
    purple: '#8b5cf6',     // Violet
    pink: '#ec4899',       // Pink
    teal: '#14b8a6',       // Teal
    slate: '#64748b',      // Slate
};

export const CHART_PALETTE = [
    CHART_COLORS.primary,
    CHART_COLORS.success,
    CHART_COLORS.warning,
    CHART_COLORS.danger,
    CHART_COLORS.info,
    CHART_COLORS.purple,
    CHART_COLORS.pink,
    CHART_COLORS.teal,
];

interface DataPoint {
    label: string;
    value: number;
    color?: string;
}

interface TimeSeriesPoint {
    date: string;
    value: number;
}

interface MultiSeriesPoint {
    date: string;
    [key: string]: number | string;
}

// ============================================
// STAT CARD
// ============================================

interface StatCardProps {
    label: string;
    value: string | number;
    change?: number;
    changeLabel?: string;
    icon?: string;
    trend?: 'up' | 'down' | 'neutral';
    format?: 'number' | 'currency' | 'percent';
}

export function StatCard({ label, value, change, changeLabel, icon, trend }: StatCardProps) {
    const trendColor = trend === 'up' ? 'text-emerald-600' : trend === 'down' ? 'text-red-600' : 'text-surface-500';
    const trendIcon = trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→';

    return (
        <div className="card p-5">
            <div className="flex items-start justify-between">
                <div>
                    <p className="text-xs font-medium text-surface-600 uppercase tracking-wide">{label}</p>
                    <p className="text-2xl font-bold text-surface-900 mt-1">{value}</p>
                    {change !== undefined && (
                        <p className={`text-xs font-medium mt-2 flex items-center gap-1 ${trendColor}`}>
                            <span>{trendIcon}</span>
                            <span>{change > 0 ? '+' : ''}{change}%</span>
                            {changeLabel && <span className="text-surface-400 ml-1">{changeLabel}</span>}
                        </p>
                    )}
                </div>
                {icon && <span className="text-2xl">{icon}</span>}
            </div>
        </div>
    );
}

// ============================================
// PROGRESS BAR
// ============================================

interface ProgressBarProps {
    value: number;
    max?: number;
    color?: string;
    showLabel?: boolean;
    size?: 'sm' | 'md' | 'lg';
}

export function ProgressBar({ value, max = 100, color = CHART_COLORS.primary, showLabel = true, size = 'md' }: ProgressBarProps) {
    const percent = Math.min((value / max) * 100, 100);
    const height = size === 'sm' ? 'h-1.5' : size === 'lg' ? 'h-4' : 'h-2.5';

    return (
        <div className="w-full">
            <div className={`w-full bg-surface-100 rounded-full overflow-hidden ${height}`}>
                <div
                    className="h-full rounded-full transition-all duration-500 ease-out"
                    style={{ width: `${percent}%`, backgroundColor: color }}
                />
            </div>
            {showLabel && (
                <div className="flex justify-between mt-1 text-xs text-surface-500">
                    <span>{value.toLocaleString()}</span>
                    <span>{max.toLocaleString()}</span>
                </div>
            )}
        </div>
    );
}

// ============================================
// DONUT CHART
// ============================================

interface DonutChartProps {
    data: DataPoint[];
    size?: number;
    thickness?: number;
    showLegend?: boolean;
    centerLabel?: string;
    centerValue?: string;
}

export function DonutChart({ data, size = 200, thickness = 40, showLegend = true, centerLabel, centerValue }: DonutChartProps) {
    const total = data.reduce((sum, d) => sum + d.value, 0);
    const radius = (size - thickness) / 2;
    const _circumference = 2 * Math.PI * radius;
    const center = size / 2;

    let currentAngle = -90; // Start from top

    const segments = data.map((d, i) => {
        const percent = d.value / total;
        const angle = percent * 360;
        const startAngle = currentAngle;
        currentAngle += angle;

        // Calculate arc path
        const startRad = (startAngle * Math.PI) / 180;
        const endRad = ((startAngle + angle) * Math.PI) / 180;
        const largeArc = angle > 180 ? 1 : 0;

        const x1 = center + radius * Math.cos(startRad);
        const y1 = center + radius * Math.sin(startRad);
        const x2 = center + radius * Math.cos(endRad);
        const y2 = center + radius * Math.sin(endRad);

        const color = d.color || CHART_PALETTE[i % CHART_PALETTE.length];

        return {
            ...d,
            path: `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2}`,
            color,
            percent: (percent * 100).toFixed(1),
        };
    });

    return (
        <div className="flex items-center gap-6">
            <div className="relative" style={{ width: size, height: size }}>
                <svg width={size} height={size} className="transform -rotate-0">
                    {segments.map((seg, i) => (
                        <path
                            key={i}
                            d={seg.path}
                            fill="none"
                            stroke={seg.color}
                            strokeWidth={thickness}
                            strokeLinecap="round"
                            className="transition-all duration-300 hover:opacity-80"
                        />
                    ))}
                </svg>
                {(centerLabel || centerValue) && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                        {centerValue && <span className="text-2xl font-bold text-surface-900">{centerValue}</span>}
                        {centerLabel && <span className="text-xs text-surface-500">{centerLabel}</span>}
                    </div>
                )}
            </div>
            {showLegend && (
                <div className="space-y-2">
                    {segments.map((seg, i) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: seg.color }} />
                            <span className="text-surface-600">{seg.label}</span>
                            <span className="text-surface-900 font-medium ml-auto">{seg.percent}%</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// ============================================
// BAR CHART
// ============================================

interface BarChartProps {
    data: DataPoint[];
    height?: number;
    showValues?: boolean;
    horizontal?: boolean;
}

export function BarChart({ data, height = 200, showValues = true, horizontal = false }: BarChartProps) {
    const maxValue = Math.max(...data.map(d => d.value));

    if (horizontal) {
        return (
            <div className="space-y-3">
                {data.map((d, i) => {
                    const percent = (d.value / maxValue) * 100;
                    const color = d.color || CHART_PALETTE[i % CHART_PALETTE.length];
                    return (
                        <div key={i}>
                            <div className="flex justify-between text-sm mb-1">
                                <span className="text-surface-600">{d.label}</span>
                                {showValues && <span className="text-surface-900 font-medium">{d.value.toLocaleString()}</span>}
                            </div>
                            <div className="h-6 bg-surface-100 rounded-lg overflow-hidden">
                                <div
                                    className="h-full rounded-lg transition-all duration-500"
                                    style={{ width: `${percent}%`, backgroundColor: color }}
                                />
                            </div>
                        </div>
                    );
                })}
            </div>
        );
    }

    const barWidth = Math.min(60, (300 / data.length) - 8);

    return (
        <div className="w-full" style={{ height }}>
            <svg width="100%" height={height} className="overflow-visible">
                {data.map((d, i) => {
                    const barHeight = (d.value / maxValue) * (height - 40);
                    const x = (i * (100 / data.length)) + (50 / data.length);
                    const color = d.color || CHART_PALETTE[i % CHART_PALETTE.length];
                    return (
                        <g key={i}>
                            <rect
                                x={`${x - (barWidth / 6)}%`}
                                y={height - barHeight - 20}
                                width={barWidth}
                                height={barHeight}
                                rx={4}
                                fill={color}
                                className="transition-all duration-300 hover:opacity-80"
                            />
                            {showValues && (
                                <text
                                    x={`${x}%`}
                                    y={height - barHeight - 25}
                                    textAnchor="middle"
                                    className="text-xs fill-surface-600 font-medium"
                                >
                                    {d.value.toLocaleString()}
                                </text>
                            )}
                            <text
                                x={`${x}%`}
                                y={height - 5}
                                textAnchor="middle"
                                className="text-xs fill-surface-500"
                            >
                                {d.label}
                            </text>
                        </g>
                    );
                })}
            </svg>
        </div>
    );
}

// ============================================
// LINE CHART (Sparkline style)
// ============================================

interface LineChartProps {
    data: TimeSeriesPoint[];
    width?: number;
    height?: number;
    color?: string;
    showArea?: boolean;
    showDots?: boolean;
    showGrid?: boolean;
}

export function LineChart({ data, width = 400, height = 150, color = CHART_COLORS.primary, showArea = true, showDots = false, showGrid = true }: LineChartProps) {
    if (data.length === 0) return null;

    const values = data.map(d => d.value);
    const maxValue = Math.max(...values);
    const minValue = Math.min(...values);
    const range = maxValue - minValue || 1;

    const padding = { top: 10, right: 10, bottom: 30, left: 50 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    const points = data.map((d, i) => ({
        x: padding.left + (i / (data.length - 1)) * chartWidth,
        y: padding.top + chartHeight - ((d.value - minValue) / range) * chartHeight,
        ...d,
    }));

    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
    const areaPath = `${linePath} L ${points[points.length - 1].x} ${padding.top + chartHeight} L ${points[0].x} ${padding.top + chartHeight} Z`;

    // Y-axis ticks
    const yTicks = [0, 0.25, 0.5, 0.75, 1].map(t => ({
        value: Math.round(minValue + t * range),
        y: padding.top + chartHeight - t * chartHeight,
    }));

    return (
        <svg width={width} height={height} className="overflow-visible">
            {/* Grid lines */}
            {showGrid && yTicks.map((tick, i) => (
                <g key={i}>
                    <line
                        x1={padding.left}
                        y1={tick.y}
                        x2={width - padding.right}
                        y2={tick.y}
                        stroke="#e2e8f0"
                        strokeDasharray="4 4"
                    />
                    <text x={padding.left - 8} y={tick.y + 4} textAnchor="end" className="text-xs fill-surface-400">
                        {tick.value.toLocaleString()}
                    </text>
                </g>
            ))}

            {/* Area fill */}
            {showArea && (
                <path d={areaPath} fill={color} fillOpacity={0.1} />
            )}

            {/* Line */}
            <path d={linePath} fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />

            {/* Dots */}
            {showDots && points.map((p, i) => (
                <circle key={i} cx={p.x} cy={p.y} r={4} fill={color} className="transition-all hover:r-6" />
            ))}

            {/* X-axis labels (show every few) */}
            {points.filter((_, i) => i % Math.ceil(data.length / 6) === 0 || i === data.length - 1).map((p, i) => (
                <text key={i} x={p.x} y={height - 8} textAnchor="middle" className="text-xs fill-surface-400">
                    {p.date}
                </text>
            ))}
        </svg>
    );
}

// ============================================
// MULTI-LINE CHART
// ============================================

interface MultiLineChartProps {
    data: MultiSeriesPoint[];
    series: { key: string; label: string; color: string }[];
    width?: number;
    height?: number;
    showLegend?: boolean;
}

export function MultiLineChart({ data, series, width = 500, height = 200, showLegend = true }: MultiLineChartProps) {
    if (data.length === 0) return null;

    const allValues = series.flatMap(s => data.map(d => d[s.key] as number));
    const maxValue = Math.max(...allValues);
    const minValue = Math.min(...allValues);
    const range = maxValue - minValue || 1;

    const padding = { top: 10, right: 10, bottom: 30, left: 50 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    return (
        <div>
            <svg width={width} height={height} className="overflow-visible">
                {/* Grid */}
                {[0, 0.5, 1].map((t, i) => (
                    <line
                        key={i}
                        x1={padding.left}
                        y1={padding.top + chartHeight - t * chartHeight}
                        x2={width - padding.right}
                        y2={padding.top + chartHeight - t * chartHeight}
                        stroke="#e2e8f0"
                        strokeDasharray="4 4"
                    />
                ))}

                {/* Lines for each series */}
                {series.map(s => {
                    const points = data.map((d, i) => ({
                        x: padding.left + (i / (data.length - 1)) * chartWidth,
                        y: padding.top + chartHeight - (((d[s.key] as number) - minValue) / range) * chartHeight,
                    }));
                    const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');

                    return (
                        <path
                            key={s.key}
                            d={path}
                            fill="none"
                            stroke={s.color}
                            strokeWidth={2}
                            strokeLinecap="round"
                            strokeLinejoin="round"
                        />
                    );
                })}
            </svg>

            {/* Legend */}
            {showLegend && (
                <div className="flex gap-4 mt-3 justify-center">
                    {series.map(s => (
                        <div key={s.key} className="flex items-center gap-2 text-sm">
                            <div className="w-3 h-0.5 rounded" style={{ backgroundColor: s.color }} />
                            <span className="text-surface-600">{s.label}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// ============================================
// METRIC SPARKLINE (Inline mini chart)
// ============================================

interface SparklineProps {
    data: number[];
    width?: number;
    height?: number;
    color?: string;
}

export function Sparkline({ data, width = 100, height = 30, color = CHART_COLORS.primary }: SparklineProps) {
    if (data.length === 0) return null;

    const max = Math.max(...data);
    const min = Math.min(...data);
    const range = max - min || 1;

    const points = data.map((v, i) => ({
        x: (i / (data.length - 1)) * width,
        y: height - ((v - min) / range) * height,
    }));

    const path = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');

    return (
        <svg width={width} height={height} className="overflow-visible">
            <path d={path} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
        </svg>
    );
}

// ============================================
// HEAT MAP (For engagement/activity)
// ============================================

interface HeatMapProps {
    data: { day: number; hour: number; value: number }[];
    width?: number;
    height?: number;
}

export function HeatMap({ data, width = 500, height = 150 }: HeatMapProps) {
    const maxValue = Math.max(...data.map(d => d.value));
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const _hours = Array.from({ length: 24 }, (_, i) => i);

    const cellWidth = (width - 40) / 24;
    const cellHeight = (height - 20) / 7;

    return (
        <svg width={width} height={height}>
            {/* Day labels */}
            {days.map((day, i) => (
                <text key={day} x={0} y={25 + i * cellHeight + cellHeight / 2} className="text-xs fill-surface-400" alignmentBaseline="middle">
                    {day}
                </text>
            ))}

            {/* Cells */}
            {data.map((d, i) => {
                const intensity = d.value / maxValue;
                const color = `rgba(59, 130, 246, ${0.1 + intensity * 0.9})`;
                return (
                    <rect
                        key={i}
                        x={40 + d.hour * cellWidth}
                        y={20 + d.day * cellHeight}
                        width={cellWidth - 2}
                        height={cellHeight - 2}
                        rx={2}
                        fill={color}
                        className="transition-all hover:stroke-blue-600 hover:stroke-1"
                    >
                        <title>{`${days[d.day]} ${d.hour}:00 - ${d.value} events`}</title>
                    </rect>
                );
            })}
        </svg>
    );
}

// ============================================
// FUNNEL CHART
// ============================================

interface FunnelChartProps {
    data: DataPoint[];
    height?: number;
}

export function FunnelChart({ data, height = 200 }: FunnelChartProps) {
    const maxValue = data[0]?.value || 1;

    return (
        <div className="space-y-2" style={{ minHeight: height }}>
            {data.map((d, i) => {
                const widthPercent = (d.value / maxValue) * 100;
                const color = d.color || CHART_PALETTE[i % CHART_PALETTE.length];
                const conversionRate = i > 0 ? ((d.value / data[i - 1].value) * 100).toFixed(1) : null;

                return (
                    <div key={i} className="relative">
                        <div
                            className="h-10 rounded-lg flex items-center justify-between px-4 transition-all duration-300"
                            style={{
                                width: `${widthPercent}%`,
                                minWidth: '120px',
                                backgroundColor: color,
                                marginLeft: `${(100 - widthPercent) / 2}%`,
                            }}
                        >
                            <span className="text-white font-medium text-sm truncate">{d.label}</span>
                            <span className="text-white/90 text-sm">{d.value.toLocaleString()}</span>
                        </div>
                        {conversionRate && (
                            <div className="absolute -right-16 top-1/2 -translate-y-1/2 text-xs text-surface-500">
                                {conversionRate}%
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
}
