class TimeSpan {
  constructor(value, unit) {
    this.value = value;
    this.unit = unit;
  }
  value;
  unit;
  milliseconds() {
    if (this.unit === "ms") {
      return this.value;
    }
    if (this.unit === "s") {
      return this.value * 1e3;
    }
    if (this.unit === "m") {
      return this.value * 1e3 * 60;
    }
    if (this.unit === "h") {
      return this.value * 1e3 * 60 * 60;
    }
    if (this.unit === "d") {
      return this.value * 1e3 * 60 * 60 * 24;
    }
    return this.value * 1e3 * 60 * 60 * 24 * 7;
  }
  seconds() {
    return this.milliseconds() / 1e3;
  }
  transform(x) {
    return new TimeSpan(Math.round(this.milliseconds() * x), "ms");
  }
}
function isWithinExpirationDate(date) {
  return Date.now() < date.getTime();
}
function createDate(timeSpan) {
  return new Date(Date.now() + timeSpan.milliseconds());
}
export {
  TimeSpan,
  createDate,
  isWithinExpirationDate
};
//# sourceMappingURL=index.js.map