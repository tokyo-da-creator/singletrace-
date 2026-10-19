"use client";

import { useEffect, useRef, useState } from "react";
import maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import type { MapPoint } from "@/lib/queries/dashboard";

function collection(points: MapPoint[]) {
  return {
    type: "FeatureCollection" as const,
    features: points.map((point) => ({
      type: "Feature" as const,
      geometry: { type: "Point" as const, coordinates: [point.longitude, point.latitude] },
      properties: {
        ip: point.ip,
        records: point.records,
        precision: point.precision ?? "network",
        country: point.countryName ?? point.countryCode ?? "",
        city: point.city ?? "",
        providers: point.providers,
        lastSeen: point.lastSeen,
      },
    })),
  };
}

function popupNode(properties: maplibregl.GeoJSONFeature["properties"]): HTMLDivElement {
  const root = document.createElement("div");
  const ip = document.createElement("div");
  ip.style.fontFamily = "var(--font-plex-mono), Consolas, monospace";
  ip.textContent = String(properties?.ip ?? "");
  const meta = document.createElement("p");
  meta.style.margin = "6px 0";
  meta.style.color = "#929292";
  meta.textContent = `${properties?.records ?? 0} records · ${properties?.city ? `${properties.city}, ` : ""}${properties?.country || "unknown country"} · ${properties?.precision} estimate`;
  const caveat = document.createElement("p");
  caveat.style.margin = "0 0 6px";
  caveat.textContent = "Network location of this IP address. Not the physical location of a threat actor.";
  const link = document.createElement("a");
  link.href = `/investigate?q=${encodeURIComponent(String(properties?.ip ?? ""))}`;
  link.textContent = "Investigate";
  link.style.color = "#eeeeee";
  link.style.textDecoration = "underline";
  root.append(ip, meta, caveat, link);
  return root;
}

export function ThreatMap({ points }: { points: MapPoint[] }) {
  const holder = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [failed, setFailed] = useState(false);
  const pointsRef = useRef(points);
  pointsRef.current = points;

  useEffect(() => {
    if (!holder.current || mapRef.current) return;
    let map: maplibregl.Map;
    try {
      map = new maplibregl.Map({
        container: holder.current,
        style: "https://tiles.openfreemap.org/styles/dark",
        center: [10, 18],
        zoom: 1.15,
        cooperativeGestures: true,
      });
    } catch {
      setFailed(true);
      return;
    }
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
    map.on("error", () => {
      if (!map.isStyleLoaded()) setFailed(true);
    });
    map.on("load", () => {
      map.addSource("obs", {
        type: "geojson",
        data: collection(pointsRef.current),
        cluster: true,
        clusterRadius: 42,
        clusterMaxZoom: 5,
      });
      map.addLayer({
        id: "clusters",
        type: "circle",
        source: "obs",
        filter: ["has", "point_count"],
        paint: {
          "circle-color": "#3a1512",
          "circle-stroke-color": "#e10600",
          "circle-stroke-width": 1,
          "circle-radius": ["step", ["get", "point_count"], 11, 8, 15, 40, 19],
        },
      });
      map.addLayer({
        id: "cluster-count",
        type: "symbol",
        source: "obs",
        filter: ["has", "point_count"],
        layout: {
          "text-field": ["get", "point_count_abbreviated"],
          "text-font": ["Noto Sans Regular"],
          "text-size": 11,
        },
        paint: { "text-color": "#eeeeee" },
      });
      map.addLayer({
        id: "points",
        type: "circle",
        source: "obs",
        filter: ["!", ["has", "point_count"]],
        paint: {
          "circle-color": "#e10600",
          "circle-radius": 4.5,
          "circle-stroke-color": "#5a0c08",
          "circle-stroke-width": 1,
        },
      });
      map.on("click", "clusters", async (event) => {
        const feature = event.features?.[0];
        const source = map.getSource("obs") as maplibregl.GeoJSONSource;
        const clusterId = feature?.properties?.cluster_id;
        if (clusterId == null) return;
        const zoom = await source.getClusterExpansionZoom(clusterId);
        const geometry = feature?.geometry;
        if (geometry?.type !== "Point") return;
        map.easeTo({ center: geometry.coordinates as [number, number], zoom });
      });
      map.on("click", "points", (event) => {
        const feature = event.features?.[0];
        if (!feature || feature.geometry.type !== "Point") return;
        new maplibregl.Popup({ closeButton: true, maxWidth: "280px" })
          .setLngLat(feature.geometry.coordinates as [number, number])
          .setDOMContent(popupNode(feature.properties))
          .addTo(map);
      });
      map.on("mouseenter", "clusters", () => {
        map.getCanvas().style.cursor = "pointer";
      });
      map.on("mouseleave", "clusters", () => {
        map.getCanvas().style.cursor = "";
      });
      map.on("mouseenter", "points", () => {
        map.getCanvas().style.cursor = "pointer";
      });
      map.on("mouseleave", "points", () => {
        map.getCanvas().style.cursor = "";
      });
    });
    mapRef.current = map;
    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const source = map?.getSource("obs") as maplibregl.GeoJSONSource | undefined;
    source?.setData(collection(points));
  }, [points]);

  if (failed) {
    return (
      <div className="flex h-[280px] items-center border border-line bg-bg px-4 text-[13px] text-muted xl:h-[460px]">
        Map tiles are unavailable. The country list still uses the stored IP geolocation cache.
      </div>
    );
  }

  return <div ref={holder} className="map-shell h-[280px] w-full xl:h-[460px]" role="region" aria-label="Map of geolocated IP indicators" />;
}
