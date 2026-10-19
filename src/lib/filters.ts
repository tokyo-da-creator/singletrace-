import { FAMILIES, type FamilyId } from "@/lib/family";
import { InputError } from "@/lib/indicators";
import { eachUtcDay, startOfUtcDay } from "@/lib/time";

export const CATEGORIES = [
  "reported_ioc",
  "malware_distribution",
  "scanner_classification",
  "vulnerability_disclosure",
  "derived",
] as const;

export type Category = (typeof CATEGORIES)[number];
export type SourceId = "all" | "threatfox" | "urlhaus" | "cisa_kev";
export type Preset = "24h" | "7d" | "30d" | "90d" | "26w" | "custom";
export type SortKey = "time_desc" | "time_asc" | "confidence_desc";

export type BBox = { north: number; south: number; east: number; west: number };

export type Filters = {
  preset: Preset;
  from: Date;
  to: Date;
  source: SourceId;
  category: "all" | Category;
  family: "all" | FamilyId;
  country: string | null;
  q: string | null;
  day: string | null;
  page: number;
  pageSize: number;
  sort: SortKey;
  bbox: BBox | null;
};

const PRESET_DAYS: Record<Exclude<Preset, "24h" | "custom">, number> = {
  "7d": 7,
  "30d": 30,
  "90d": 90,
  "26w": 182,
};

function one(params: URLSearchParams, key: string): string {
  return params.get(key)?.trim() ?? "";
}

function parseDay(value: string, label: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new InputError(`${label} must be a UTC date in YYYY-MM-DD form.`);
  }
  const date = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) throw new InputError(`${label} is not a valid date.`);
  return date;
}

export function parseFilters(params: URLSearchParams, now = new Date()): Filters {
  const presetRaw = one(params, "range") || "26w";
  const preset = (["24h", "7d", "30d", "90d", "26w", "custom"] as const).find((item) => item === presetRaw);
  if (!preset) throw new InputError("Time range must be 24h, 7d, 30d, 90d, 26w, or custom.");

  let from: Date;
  let to: Date;
  if (preset === "24h") {
    to = now;
    from = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  } else if (preset === "custom") {
    from = parseDay(one(params, "from"), "From");
    const inclusive = parseDay(one(params, "to"), "To");
    to = new Date(inclusive.getTime() + 24 * 60 * 60 * 1000);
    if (to <= from) throw new InputError("The end date must be on or after the start date.");
  } else {
    const today = startOfUtcDay(now);
    to = new Date(today.getTime() + 24 * 60 * 60 * 1000);
    from = new Date(today.getTime() - (PRESET_DAYS[preset] - 1) * 24 * 60 * 60 * 1000);
  }

  const spanDays = (to.getTime() - from.getTime()) / 86400000;
  if (spanDays > 400) throw new InputError("Time range cannot exceed 400 days.");

  const sourceRaw = one(params, "source") || "threatfox";
  const source = (["all", "threatfox", "urlhaus", "cisa_kev"] as const).find((item) => item === sourceRaw);
  if (!source) throw new InputError("Unknown source filter.");

  const categoryRaw = one(params, "category") || "all";
  const category = categoryRaw === "all" ? "all" : CATEGORIES.find((item) => item === categoryRaw);
  if (!category) throw new InputError("Unknown category filter.");

  const familyRaw = one(params, "family") || "all";
  const family = familyRaw === "all" ? "all" : FAMILIES.find((item) => item.id === familyRaw)?.id;
  if (!family) throw new InputError("Unknown family filter.");

  const countryRaw = one(params, "country").toUpperCase();
  if (countryRaw && !/^[A-Z]{2}$/.test(countryRaw)) throw new InputError("Country must be a two-letter code.");

  const qRaw = one(params, "q");
  if (qRaw.length > 200) throw new InputError("Search text cannot exceed 200 characters.");

  const dayRaw = one(params, "day");
  let day: string | null = null;
  if (dayRaw) {
    const selected = parseDay(dayRaw, "Day");
    if (selected < startOfUtcDay(from) || selected >= to) {
      throw new InputError("The selected day is outside the time range.");
    }
    day = dayRaw;
  }

  const page = Number(one(params, "page") || "1");
  if (!Number.isInteger(page) || page < 1 || page > 200) throw new InputError("Page must be between 1 and 200.");
  const pageSize = Number(one(params, "pageSize") || "25");
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
    throw new InputError("Page size must be between 1 and 100.");
  }

  const sortRaw = one(params, "sort") || "time_desc";
  const sort = (["time_desc", "time_asc", "confidence_desc"] as const).find((item) => item === sortRaw);
  if (!sort) throw new InputError("Unknown sort.");

  const bboxValues = ["north", "south", "east", "west"].map((key) => one(params, key));
  let bbox: BBox | null = null;
  if (bboxValues.some((value) => value)) {
    if (bboxValues.some((value) => value === "" || Number.isNaN(Number(value)))) {
      throw new InputError("A map box needs north, south, east, and west.");
    }
    const [north, south, east, west] = bboxValues.map(Number);
    if (north < south || north > 90 || south < -90 || east > 180 || west < -180) {
      throw new InputError("Map box coordinates are out of range.");
    }
    bbox = { north, south, east, west };
  }

  return {
    preset,
    from,
    to,
    source,
    category,
    family,
    country: countryRaw || null,
    q: qRaw || null,
    day,
    page,
    pageSize,
    sort,
    bbox,
  };
}

export function filterQuery(filters: Filters, overrides: Record<string, string | null> = {}): string {
  const params = new URLSearchParams();
  const preset = overrides.range ?? filters.preset;
  params.set("range", preset);
  if (preset === "custom") {
    params.set("from", overrides.from ?? filters.from.toISOString().slice(0, 10));
    const inclusive = new Date(filters.to.getTime() - 1);
    params.set("to", overrides.to ?? inclusive.toISOString().slice(0, 10));
  }
  const source = overrides.source ?? filters.source;
  if (source && source !== "threatfox") params.set("source", source);
  if (overrides.source === "threatfox") params.delete("source");
  const category = overrides.category ?? (filters.category === "all" ? null : filters.category);
  if (category) params.set("category", category);
  const family = overrides.family ?? (filters.family === "all" ? null : filters.family);
  if (family) params.set("family", family);
  const country = overrides.country === undefined ? filters.country : overrides.country;
  if (country) params.set("country", country);
  const q = overrides.q === undefined ? filters.q : overrides.q;
  if (q) params.set("q", q);
  const day = overrides.day === undefined ? filters.day : overrides.day;
  if (day) params.set("day", day);
  if (filters.bbox && overrides.keepBox !== "0") {
    params.set("north", String(filters.bbox.north));
    params.set("south", String(filters.bbox.south));
    params.set("east", String(filters.bbox.east));
    params.set("west", String(filters.bbox.west));
  }
  const page = overrides.page;
  if (page && page !== "1") params.set("page", page);
  if (filters.sort !== "time_desc" && !overrides.sort) params.set("sort", filters.sort);
  if (overrides.sort && overrides.sort !== "time_desc") params.set("sort", overrides.sort);
  const text = params.toString();
  return text ? `/?${text}` : "/";
}

export function windowDays(filters: Filters): string[] {
  return eachUtcDay(filters.from, filters.to);
}

export class Where {
  readonly params: unknown[] = [];
  private readonly parts: string[] = [];

  add(clause: string, ...values: unknown[]): void {
    let sql = clause;
    for (const value of values) {
      this.params.push(value);
      sql = sql.replace("?", `$${this.params.length}`);
    }
    this.parts.push(sql);
  }

  get text(): string {
    return this.parts.length ? `WHERE ${this.parts.join(" AND ")}` : "";
  }
}

function likePattern(value: string): string {
  return `%${value.replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
}

export function observationWhere(
  filters: Filters,
  ignore: Array<"country" | "source" | "category" | "family" | "q" | "bbox" | "day"> = [],
): Where {
  const where = new Where();
  where.add("is_simulated = false");
  const useDay = filters.day && !ignore.includes("day");
  if (useDay && filters.day) {
    where.add("observed_at >= ?", `${filters.day}T00:00:00.000Z`);
    where.add("observed_at < ?", new Date(Date.parse(`${filters.day}T00:00:00.000Z`) + 86400000).toISOString());
  } else {
    where.add("observed_at >= ?", filters.from.toISOString());
    where.add("observed_at < ?", filters.to.toISOString());
  }
  if (filters.source !== "all" && !ignore.includes("source")) where.add("provider_id = ?", filters.source);
  if (filters.category !== "all" && !ignore.includes("category")) where.add("category = ?", filters.category);
  if (filters.family !== "all" && !ignore.includes("family")) where.add("derived_label = ?", filters.family);
  if (filters.country && !ignore.includes("country")) where.add("country_code = ?", filters.country);
  if (filters.q && !ignore.includes("q")) {
    where.add(
      "(indicator_normalized ILIKE ? ESCAPE '\\' OR COALESCE(indicator_value, '') ILIKE ? ESCAPE '\\' OR COALESCE(malware_family, '') ILIKE ? ESCAPE '\\' OR COALESCE(summary, '') ILIKE ? ESCAPE '\\')",
      likePattern(filters.q),
      likePattern(filters.q),
      likePattern(filters.q),
      likePattern(filters.q),
    );
  }
  if (filters.bbox && !ignore.includes("bbox")) {
    where.add("latitude BETWEEN ? AND ?", filters.bbox.south, filters.bbox.north);
    if (filters.bbox.west <= filters.bbox.east) {
      where.add("longitude BETWEEN ? AND ?", filters.bbox.west, filters.bbox.east);
    } else {
      where.add("(longitude >= ? OR longitude <= ?)", filters.bbox.west, filters.bbox.east);
    }
  }
  return where;
}

export function sortSql(sort: SortKey): string {
  if (sort === "time_asc") return "observed_at ASC, id ASC";
  if (sort === "confidence_desc") return "confidence DESC NULLS LAST, observed_at DESC, id DESC";
  return "observed_at DESC, id DESC";
}

export function toSearchParams(input: Record<string, string | string[] | undefined>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string") params.set(key, value);
    else if (Array.isArray(value) && value[0]) params.set(key, value[0]);
  }
  return params;
}
