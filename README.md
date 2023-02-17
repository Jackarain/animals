# animals
[![actions workflow](https://github.com/jackarain/animals/actions/workflows/Build.yml/badge.svg)](https://github.com/Jackarain/animals/actions)

animals 是一个对 boost.beast 作为 http/websocket 客户端的更高层次抽象实现，并增加常用的功能如 ssl，socks/http 代理等支持，以更易于使用为目标。

animals 不打算提供同步 API 接口，因为同步 API 可以通过对异步 API 的简单包装来完成。
