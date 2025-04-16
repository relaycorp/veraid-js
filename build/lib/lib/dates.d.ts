export interface IDatePeriod {
    readonly start: Date;
    readonly end: Date;
}
export declare class DatePeriod implements IDatePeriod {
    readonly start: Date;
    readonly end: Date;
    static init(start: Date, end: Date): DatePeriod;
    protected constructor(start: Date, end: Date);
    overlaps(otherStart: Date, otherEnd: Date): boolean;
    intersect(otherPeriod: DatePeriod): DatePeriod | undefined;
    toString(): string;
}
