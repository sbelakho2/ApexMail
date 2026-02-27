export class ThompsonSamplerMock<T = string> {
    private arms: Map<string, { id: string; value: T; alpha: number; beta: number }> = new Map();

    addArm(id: string, value: T): void {
        this.arms.set(id, { id, value, alpha: 1, beta: 1 });
    }

    select(): { armId: string; value: T } | null {
        if (this.arms.size === 0) return null;

        let bestArm: { id: string; value: T; sample: number } | null = null;

        for (const [id, arm] of this.arms) {
            const sample = this.sampleBeta(arm.alpha, arm.beta);
            if (!bestArm || sample > bestArm.sample) {
                bestArm = { id, value: arm.value, sample };
            }
        }

        return bestArm ? { armId: bestArm.id, value: bestArm.value } : null;
    }

    recordOutcome(armId: string, success: boolean): void {
        const arm = this.arms.get(armId);
        if (arm) {
            if (success) {
                arm.alpha += 1;
            } else {
                arm.beta += 1;
            }
        }
    }

    private sampleBeta(alpha: number, beta: number): number {
        const gamma = (shape: number) => {
            let sum = 0;
            for (let i = 0; i < Math.floor(shape); i++) {
                sum -= Math.log(Math.random());
            }
            return sum;
        };
        const x = gamma(alpha);
        const y = gamma(beta);
        return x / (x + y);
    }

    getArm(id: string) {
        return this.arms.get(id);
    }

    getAllArms() {
        return Array.from(this.arms.values());
    }
}

export class UCBBanditMock<T = string> {
    private arms: Map<string, {
        id: string;
        value: T;
        pulls: number;
        totalReward: number;
    }> = new Map();
    private totalPulls = 0;

    addArm(id: string, value: T): void {
        this.arms.set(id, { id, value, pulls: 0, totalReward: 0 });
    }

    select(): { armId: string; value: T; ucbValue: number } | null {
        if (this.arms.size === 0) return null;

        for (const [id, arm] of this.arms) {
            if (arm.pulls === 0) {
                return { armId: id, value: arm.value, ucbValue: Infinity };
            }
        }

        let bestArm: { id: string; value: T; ucbValue: number } | null = null;

        for (const [id, arm] of this.arms) {
            const mean = arm.totalReward / arm.pulls;
            const exploration = Math.sqrt(2 * Math.log(this.totalPulls) / arm.pulls);
            const ucbValue = mean + exploration;

            if (!bestArm || ucbValue > bestArm.ucbValue) {
                bestArm = { id, value: arm.value, ucbValue };
            }
        }

        return bestArm ? { armId: bestArm.id, value: bestArm.value, ucbValue: bestArm.ucbValue } : null;
    }

    recordReward(armId: string, reward: number): void {
        const arm = this.arms.get(armId);
        if (arm) {
            arm.pulls++;
            arm.totalReward += reward;
            this.totalPulls++;
        }
    }

    getArm(id: string) {
        return this.arms.get(id);
    }

    getMean(id: string): number {
        const arm = this.arms.get(id);
        if (!arm || arm.pulls === 0) return 0;
        return arm.totalReward / arm.pulls;
    }
}
