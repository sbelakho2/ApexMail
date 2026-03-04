import { Check, X, Minus, Trophy } from '@/components/ui/icons';
import { cn } from '@/lib/utils';

interface Feature {
  name: string;
  apexmail: string;
  competitor: string;
  winner: 'apexmail' | 'competitor' | 'tie';
}

interface Category {
  name: string;
  features: readonly Feature[];
}

interface CompareTableProps {
  categories: readonly Category[];
  competitorName: string;
}

function renderValue(value: string, isWinner: boolean) {
  const lowerValue = value.toLowerCase();
  
  if (lowerValue === 'yes' || lowerValue === 'true') {
    return (
      <span className={cn('flex items-center justify-center gap-1', isWinner && 'text-primary-600 font-semibold')}>
        <Check className="w-5 h-5" />
      </span>
    );
  }
  
  if (lowerValue === 'no' || lowerValue === 'false' || lowerValue === 'none') {
    return (
      <span className="flex items-center justify-center text-surface-400">
        <X className="w-5 h-5" />
      </span>
    );
  }
  
  return (
    <span className={cn('text-sm', isWinner ? 'text-primary-600 font-semibold' : 'text-surface-600')}>
      {value}
    </span>
  );
}

export function CompareTable({ categories, competitorName }: CompareTableProps) {
  // Count wins
  const wins = categories.reduce(
    (acc, category) => {
      category.features.forEach((feature) => {
        if (feature.winner === 'apexmail') acc.apexmail++;
        else if (feature.winner === 'competitor') acc.competitor++;
      });
      return acc;
    },
    { apexmail: 0, competitor: 0 }
  );

  return (
    <section id="comparison" className="py-20 lg:py-32 bg-white">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Score Summary */}
        <div className="animate-in flex justify-center gap-8 mb-12">
          <div className="text-center">
            <div className="text-4xl font-bold text-primary-600">{wins.apexmail}</div>
            <div className="text-sm text-surface-600 font-medium">ApexMail Wins</div>
          </div>
          <div className="text-center">
            <div className="text-4xl font-bold text-surface-400">{wins.competitor}</div>
            <div className="text-sm text-surface-600 font-medium">{competitorName} Wins</div>
          </div>
        </div>

        {/* Comparison Table */}
        <div className="animate-in delay-200 bg-white rounded-lg border border-surface-200 shadow-sm overflow-x-auto">
          <div className="min-w-[760px]">
          {/* Table Header */}
          <div className="grid grid-cols-4 gap-4 p-6 border-b border-surface-200 bg-surface-50">
            <div className="font-bold text-surface-600 text-xs self-center">
              Feature
            </div>
            <div className="text-center">
              <div className="font-bold text-primary-600 flex items-center justify-center gap-2">
                <Trophy className="w-4 h-4" />
                ApexMail
              </div>
            </div>
            <div className="text-center font-medium text-surface-900 self-center">{competitorName}</div>
            <div className="text-center font-bold text-surface-600 text-xs self-center">
              Winner
            </div>
          </div>

          {/* Categories */}
          {categories.map((category, categoryIndex) => (
            <div key={category.name}>
              {/* Category Header */}
              <div className="px-6 py-3 bg-surface-50/50 border-b border-surface-100">
                <span className="text-xs font-bold text-surface-600">
                  {category.name}
                </span>
              </div>

              {/* Features */}
              {category.features.map((feature, featureIndex) => (
                <div key={feature.name} className={cn( 'grid grid-cols-4 gap-4 px-6 py-4 items-center hover:bg-surface-50 transition-colors', featureIndex !== category.features.length - 1 && 'border-b border-surface-100' )}>
                  <div className="text-sm font-medium text-surface-700">{feature.name}</div>
                  <div className="flex justify-center">
                    {renderValue(feature.apexmail, feature.winner === 'apexmail')}
                  </div>
                  <div className="flex justify-center">
                    {renderValue(feature.competitor, feature.winner === 'competitor')}
                  </div>
                  <div className="flex justify-center">
                    {feature.winner === 'apexmail' && (
                      <span className="px-2 py-1 text-xs font-bold bg-primary-100 text-primary-700 rounded-md">
                        ApexMail
                      </span>
                    )}
                    {feature.winner === 'competitor' && (
                      <span className="px-2 py-1 text-xs font-medium bg-surface-100 text-surface-600 rounded-md">
                        {competitorName}
                      </span>
                    )}
                    {feature.winner === 'tie' && (
                      <span className="flex items-center gap-1 text-xs text-surface-400">
                        <Minus className="w-4 h-4" />
                        Tie
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ))}
          </div>
        </div>
      </div>
    </section>
  );
}
