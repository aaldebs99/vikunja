import {HTTPFactory} from '@/helpers/fetcher'
import {isDesktopApp, refreshDesktopToken} from '@/helpers/desktopAuth'

const REFRESH_TOKEN_KEY = 'vikunja_refresh_token'

let savedToken: string | null = null

/**
 * Saves a token while optionally saving it to local storage. This is used when viewing a link share:
 * It enables viewing multiple link shares independently from each in multiple tabs other without overriding any other open ones.
 */
export const saveToken = (token: string, persist: boolean) => {
	savedToken = token
	if (persist) {
		localStorage.setItem('token', token)
	}
}

/**
 * Saves the refresh token to localStorage.
 * This serves as a fallback for environments where HttpOnly cookies are not
 * reliably persisted (e.g. iOS PWAs that clear cookies on app restart).
 */
export const saveRefreshToken = (refreshToken: string) => {
	if (refreshToken) {
		localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
	}
}

/**
 * Returns the refresh token from localStorage, if any.
 */
export const getRefreshToken = (): string | null => {
	return localStorage.getItem(REFRESH_TOKEN_KEY)
}

/**
 * Returns a saved token. If there is one saved in memory it will use that before anything else.
 */
export const getToken = (): string | null => {
	if (savedToken !== null) {
		return savedToken
	}

	savedToken = localStorage.getItem('token')
	return savedToken
}

/**
 * Removes all tokens everywhere.
 */
export const removeToken = () => {
	savedToken = null
	localStorage.removeItem('token')
	localStorage.removeItem('desktopOAuthRefreshToken')
	localStorage.removeItem(REFRESH_TOKEN_KEY)
}

/**
 * Refreshes an auth token while ensuring it is updated everywhere.
 * The refresh token is sent automatically as an HttpOnly cookie.
 * The server rotates the cookie on every call.
 *
 * Uses the Web Locks API to coordinate across browser tabs. Only one tab
 * performs the actual refresh; other tabs waiting for the lock detect that
 * the token in localStorage was already updated and adopt it directly.
 */
export async function refreshToken(persist: boolean): Promise<void> {
	// In desktop mode, refresh via IPC to the Electron main process
	if (isDesktopApp()) {
		const storedRefreshToken = localStorage.getItem('desktopOAuthRefreshToken')
		if (!storedRefreshToken) {
			throw new Error('No desktop OAuth refresh token available')
		}
		try {
			const tokens = await refreshDesktopToken(window.API_URL, storedRefreshToken)
			saveToken(tokens.access_token, persist)
			localStorage.setItem('desktopOAuthRefreshToken', tokens.refresh_token)
		} catch (e) {
			throw new Error('Error renewing token: ', {cause: e})
		}
		return
	}

	// Capture the token before waiting for the lock so we can detect
	// if another tab refreshed while we were queued.
	const tokenBeforeLock = localStorage.getItem('token')

	const doRefresh = async () => {
		// If the token in localStorage changed while waiting for the lock,
		// another tab already refreshed. Just adopt the new token.
		const currentToken = localStorage.getItem('token')
		if (currentToken && currentToken !== tokenBeforeLock) {
			savedToken = currentToken
			return
		}

		// We hold the lock and no one else refreshed — make the API call.
		// The refresh token is normally sent as an HttpOnly cookie by the
		// browser. As a fallback for environments that don't reliably
		// persist cookies (iOS PWAs), we also send it in the request body.
		const HTTP = HTTPFactory()
		try {
			const storedRefresh = getRefreshToken()
			const body = storedRefresh ? {refresh_token: storedRefresh} : {}
			const response = await HTTP.post('user/token/refresh', body)
			saveToken(response.data.token, persist)
			if (response.data.refresh_token) {
				saveRefreshToken(response.data.refresh_token)
			}
		} catch (e) {
			throw new Error('Error renewing token: ', {cause: e})
		}
	}

	if (navigator.locks) {
		await navigator.locks.request('vikunja-token-refresh', doRefresh)
	} else {
		// Fallback for environments without Web Locks (e.g. insecure HTTP)
		await doRefresh()
	}
}

