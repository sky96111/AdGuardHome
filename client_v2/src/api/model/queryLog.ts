import type { QueryLogItem } from './queryLogItem';

/**
 * Query log
 */
export interface QueryLog {
    oldest?: string;
    /**
     * The row ID of the oldest returned entry, to be passed back in the
     * "older_than_id" parameter.  It's absent when the entries didn't come
     * from the database.
     */
    oldest_id?: number;
    data?: QueryLogItem[];
}
