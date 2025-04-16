export class DatePeriod {
    static init(start, end) {
        if (end < start) {
            throw new Error(`End date should not be before start date (${start.toISOString()} <= ${end.toISOString()})`);
        }
        return new DatePeriod(start, end);
    }
    constructor(start, end) {
        this.start = start;
        this.end = end;
    }
    overlaps(otherStart, otherEnd) {
        if (otherEnd < otherStart) {
            // The other date period is invalid
            return false;
        }
        if (otherEnd < this.start) {
            return false;
        }
        return otherStart <= this.end;
    }
    intersect(otherPeriod) {
        if (!this.overlaps(otherPeriod.start, otherPeriod.end)) {
            return undefined;
        }
        const start = this.start < otherPeriod.start ? otherPeriod.start : this.start;
        const end = this.end < otherPeriod.end ? this.end : otherPeriod.end;
        return new DatePeriod(start, end);
    }
    toString() {
        return `${this.start.toISOString()}..${this.end.toISOString()}`;
    }
}
//# sourceMappingURL=dates.js.map