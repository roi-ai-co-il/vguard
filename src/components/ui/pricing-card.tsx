import * as React from 'react'
import { Check, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

export type BillingCycle = 'monthly' | 'annually'

export interface Feature {
  name: string
  isIncluded: boolean
  tooltip?: string
}

export interface PriceTier {
  id: string
  name: string
  description: string
  priceMonthly: number
  priceAnnually: number
  isPopular: boolean
  buttonLabel: string
  currency?: string
  features: Feature[]
}

export interface PricingComponentProps extends React.HTMLAttributes<HTMLDivElement> {
  plans: [PriceTier, PriceTier, PriceTier]
  billingCycle: BillingCycle
  onCycleChange: (cycle: BillingCycle) => void
  onPlanSelect: (planId: string, cycle: BillingCycle) => void
  heading?: React.ReactNode
  subheading?: React.ReactNode
  annualDiscountPercent?: number
}

const FeatureItem: React.FC<{ feature: Feature }> = ({ feature }) => {
  const Icon = feature.isIncluded ? Check : X
  const iconColor = feature.isIncluded ? 'text-primary' : 'text-muted-foreground'

  return (
    <li className="flex items-start space-x-3 py-2">
      <Icon
        className={cn('h-4 w-4 flex-shrink-0 mt-0.5', iconColor)}
        aria-hidden="true"
      />
      <span
        className={cn(
          'text-sm',
          feature.isIncluded ? 'text-foreground' : 'text-muted-foreground',
        )}
      >
        {feature.name}
      </span>
    </li>
  )
}

export const PricingComponent: React.FC<PricingComponentProps> = ({
  plans,
  billingCycle,
  onCycleChange,
  onPlanSelect,
  className,
  heading = 'Choose the right plan for your business.',
  subheading = 'Scale effortlessly with features designed for growth, from startups to enterprise.',
  annualDiscountPercent = 20,
  ...props
}) => {
  if (plans.length !== 3) {
    console.error('PricingComponent requires exactly 3 pricing tiers.')
    return null
  }

  const CycleToggle = (
    <div className="flex justify-center mb-12 mt-2">
      <ToggleGroup
        type="single"
        value={billingCycle}
        onValueChange={(value) => {
          if (value === 'monthly' || value === 'annually') {
            onCycleChange(value)
          }
        }}
        aria-label="Select billing cycle"
        className="border border-border rounded-lg p-1 bg-(--color-surface)"
      >
        <ToggleGroupItem
          value="monthly"
          aria-label="Monthly Billing"
          className="px-6 py-1.5 text-sm font-medium rounded-md transition-colors"
        >
          Monthly
        </ToggleGroupItem>
        <ToggleGroupItem
          value="annually"
          aria-label="Annual Billing"
          className="px-6 py-1.5 text-sm font-medium rounded-md transition-colors relative"
        >
          Annually
          <span className="absolute -top-3 -right-2 text-[10px] font-mono font-semibold text-primary bg-(--color-accent-muted) border border-(--color-accent-border) px-1.5 py-0.5 rounded-full whitespace-nowrap">
            Save {annualDiscountPercent}%
          </span>
        </ToggleGroupItem>
      </ToggleGroup>
    </div>
  )

  const allFeatures = Array.from(
    new Set(plans.flatMap((p) => p.features.map((f) => f.name))),
  )

  const PricingCards = (
    <div className="grid gap-6 md:grid-cols-3 md:gap-5 lg:gap-6">
      {plans.map((plan) => {
        const isFeatured = plan.isPopular
        const currentPrice =
          billingCycle === 'monthly' ? plan.priceMonthly : plan.priceAnnually
        const priceSuffix = billingCycle === 'monthly' ? '/mo' : '/yr'
        const currency = plan.currency ?? '$'

        return (
          <Card
            key={plan.id}
            className={cn(
              'flex flex-col transition-all duration-300 bg-(--color-surface) border-border',
              'hover:border-(--color-accent-border)/50',
              isFeatured &&
                'border-(--color-accent-border) shadow-[0_0_60px_-20px_rgba(34,211,238,0.4)] md:scale-[1.02]',
            )}
          >
            <CardHeader className="p-6 pb-4">
              <div className="flex justify-between items-start gap-3">
                <CardTitle className="text-xl font-semibold tracking-tight">
                  {plan.name}
                </CardTitle>
                {isFeatured && (
                  <span className="text-[10px] font-mono font-semibold tracking-widest uppercase px-2.5 py-1 bg-(--color-accent-muted) border border-(--color-accent-border) text-primary rounded-full">
                    Most Popular
                  </span>
                )}
              </div>
              <CardDescription className="text-sm mt-1.5">{plan.description}</CardDescription>
              <div className="mt-5">
                <p className="text-4xl font-bold text-foreground tracking-tight tabular-nums">
                  {currency}
                  {currentPrice}
                  <span className="text-base font-normal text-muted-foreground ml-1.5">
                    {priceSuffix}
                  </span>
                </p>
                {billingCycle === 'annually' && (
                  <p className="text-xs text-muted-foreground mt-2 font-mono">
                    Billed annually ({currency}
                    {plan.priceAnnually})
                  </p>
                )}
              </div>
            </CardHeader>
            <CardContent className="flex-grow p-6 pt-0">
              <h4 className="text-[11px] font-mono tracking-widest uppercase text-(--color-fg-dim) mb-2 mt-4">
                Includes
              </h4>
              <ul className="list-none space-y-0">
                {plan.features.slice(0, 6).map((feature) => (
                  <FeatureItem key={feature.name} feature={feature} />
                ))}
                {plan.features.length > 6 && (
                  <li className="text-sm text-muted-foreground mt-2 font-mono">
                    + {plan.features.length - 6} more
                  </li>
                )}
              </ul>
            </CardContent>
            <CardFooter className="p-6 pt-0">
              <Button
                onClick={() => onPlanSelect(plan.id, billingCycle)}
                className={cn(
                  'w-full transition-all duration-200',
                  isFeatured
                    ? 'bg-primary hover:bg-(--color-accent-strong) text-primary-foreground shadow-lg shadow-primary/20'
                    : 'bg-(--color-surface-elevated) text-foreground hover:bg-(--color-bg) border border-input hover:border-(--color-accent-border)',
                )}
                size="lg"
                aria-label={`Select ${plan.name} plan for ${currency}${currentPrice}${priceSuffix}`}
              >
                {plan.buttonLabel}
              </Button>
            </CardFooter>
          </Card>
        )
      })}
    </div>
  )

  const ComparisonTable = (
    <div className="mt-16 hidden md:block border border-border rounded-lg overflow-x-auto bg-(--color-surface)">
      <table className="min-w-full divide-y divide-border">
        <thead>
          <tr className="bg-(--color-surface-elevated)">
            <th
              scope="col"
              className="px-6 py-4 text-left text-xs font-mono tracking-widest uppercase text-(--color-fg-dim) w-[220px] whitespace-nowrap"
            >
              Feature
            </th>
            {plans.map((plan) => (
              <th
                key={`th-${plan.id}`}
                scope="col"
                className={cn(
                  'px-6 py-4 text-center text-xs font-mono tracking-widest uppercase text-(--color-fg-dim) whitespace-nowrap',
                  plan.isPopular && 'text-primary',
                )}
              >
                {plan.name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {allFeatures.map((featureName) => (
            <tr
              key={featureName}
              className="transition-colors hover:bg-(--color-surface-elevated)"
            >
              <td className="px-6 py-3 text-left text-sm font-medium text-foreground/90 whitespace-nowrap">
                {featureName}
              </td>
              {plans.map((plan) => {
                const feature = plan.features.find((f) => f.name === featureName)
                const isIncluded = feature?.isIncluded ?? false
                const Icon = isIncluded ? Check : X
                const iconColor = isIncluded ? 'text-primary' : 'text-(--color-fg-dim)'

                return (
                  <td
                    key={`${plan.id}-${featureName}`}
                    className={cn(
                      'px-6 py-3 text-center transition-all duration-150',
                      plan.isPopular && 'bg-(--color-accent-muted)/30',
                    )}
                  >
                    <Icon className={cn('h-4 w-4 mx-auto', iconColor)} aria-hidden="true" />
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  return (
    <div
      className={cn(
        'w-full py-12 md:py-20 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8',
        className,
      )}
      {...props}
    >
      <header className="text-center mb-10 max-w-2xl mx-auto">
        <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-foreground">
          {heading}
        </h2>
        <p className="mt-3 text-base text-muted-foreground">{subheading}</p>
      </header>

      {CycleToggle}

      <section aria-labelledby="pricing-plans">{PricingCards}</section>

      <section aria-label="Feature Comparison Table" className="mt-16">
        <h3 className="text-xl font-semibold mb-6 hidden md:block text-center text-foreground tracking-tight">
          Detailed Feature Comparison
        </h3>
        {ComparisonTable}
      </section>
    </div>
  )
}

export default PricingComponent
