/// One load/retry primitive for route data. A key identifies the resource; a loader reads it.

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, asApiError } from "../api";

export interface Resource<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload(): void;
}

export function useResource<T>(key: string, load: () => Promise<T>): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    loadRef.current().then(
      (value) => {
        if (cancelled) return;
        setData(value);
        setError(null);
        setLoading(false);
      },
      (failure: unknown) => {
        if (cancelled) return;
        setData(null);
        setError(asApiError(failure));
        setLoading(false);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [key, nonce]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  return { data, error, loading, reload };
}
