#define chDIMOF(Array) (sizeof(Array) / sizeof(Array[0]))

#define chHANDLE_DLGMSG(hwnd, message, fn) \
	case (message): return SetDlgMsgResult( \
		hwnd, \
		uMsg, \
		HANDLE_##message((hwnd), (wParam), (lParam), (fn)))

inline void chSETDLGICONS(HWND hwnd, int idi) {
	SendMessage(
		hwnd,
		WM_SETICON,
		TRUE,
		(LPARAM)LoadIcon((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), MAKEINTRESOURCE(idi)));
	SendMessage(
		hwnd,
		WM_SETICON,
		FALSE,
		(LPARAM)LoadIcon((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), MAKEINTRESOURCE(idi)));
}

inline void chMB(PCSTR s) {
	char szTMP[128];
	GetModuleFileNameA(NULL, szTMP, chDIMOF(szTMP));
	MessageBoxA(GetActiveWindow(), s, szTMP, MB_OK);
}
