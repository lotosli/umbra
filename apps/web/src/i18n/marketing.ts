import type { Locale } from '../lib/locales';

export type MarketingPageName =
  'home' | 'download' | 'protocol' | 'security' | 'changelog';
export interface MarketingCopy {
  nav: {
    docs: string;
    protocol: string;
    download: string;
    security: string;
    changelog: string;
    github: string;
  };
  ui: {
    language: string;
    theme: string;
    menu: string;
    skip: string;
    copy: string;
    copied: string;
    copyFailed: string;
    close: string;
  };
  pages: Record<MarketingPageName, { title: string; description: string }>;
  hero: {
    badge: string;
    title: string;
    accent: string;
    description: string;
    start: string;
    explore: string;
    footnote: string;
  };
  diagram: {
    client: string;
    transport: string;
    internet: string;
    cover: string;
    authenticated: string;
    fallback: string;
    caption: string;
  };
  facts: readonly [string, string, string, string];
  principles: {
    eyebrow: string;
    title: string;
    description: string;
    features: readonly { title: string; description: string }[];
  };
  start: {
    eyebrow: string;
    title: string;
    description: string;
    link: string;
    terminal: string;
  };
  docs: {
    eyebrow: string;
    title: string;
    description: string;
    cards: readonly { title: string; description: string }[];
  };
  cta: { title: string; description: string };
  footer: {
    description: string;
    project: string;
    resources: string;
    legal: string;
    license: string;
  };
  download: {
    eyebrow: string;
    title: string;
    description: string;
    alpha: string;
    platform: string;
    architecture: string;
    releases: string;
    source: string;
    sourceDescription: string;
    verify: string;
    verifyDescription: string;
    requirements: string;
  };
  protocol: {
    eyebrow: string;
    title: string;
    description: string;
    steps: readonly { title: string; description: string }[];
    implementation: string;
    implementationDescription: string;
    strengthsLabel: string;
    limitsLabel: string;
    layers: readonly {
      title: string;
      description: string;
      strengths: readonly string[];
      limits: readonly string[];
    }[];
    caveat: string;
  };
  security: {
    eyebrow: string;
    title: string;
    description: string;
    principles: readonly { title: string; description: string }[];
    limitsTitle: string;
    limits: readonly string[];
    disclosure: string;
    disclosureDescription: string;
    source: string;
  };
  changelog: {
    eyebrow: string;
    title: string;
    description: string;
    prerelease: string;
    heading: string;
    summary: string;
    changes: readonly string[];
    upgrade: string;
    read: string;
  };
}

const en: MarketingCopy = {
  nav: {
    docs: 'Documentation',
    protocol: 'Protocol',
    download: 'Download',
    security: 'Security',
    changelog: 'Changelog',
    github: 'GitHub',
  },
  ui: {
    language: 'Language',
    theme: 'Toggle color theme',
    menu: 'Open navigation',
    skip: 'Skip to content',
    copy: 'Copy commands',
    copied: 'Copied',
    copyFailed: 'Select and copy the commands below',
    close: 'Close',
  },
  pages: {
    home: {
      title: 'Your connection. Your server.',
      description:
        'Self-host your privacy transport with Umbra’s CLI client and server. Real-site cover, TCP or QUIC, and local SOCKS5 for your existing apps.',
    },
    download: {
      title: 'Get Umbra',
      description:
        'Find Umbra builds for macOS, Linux and Windows in the available release assets, or build the client and server from source.',
    },
    protocol: {
      title: 'Understand the options. Choose your setup.',
      description:
        'Understand Umbra’s real-site cover, Vision and TCP/QUIC choices, then compare the trade-offs with other proxy solutions.',
    },
    security: {
      title: 'Trust starts with clarity',
      description:
        'Understand Umbra’s security model, deployment responsibilities and current alpha limitations.',
    },
    changelog: {
      title: 'What changes for you',
      description:
        'Follow Umbra releases, connection handling updates and guidance for upgrading both endpoints.',
    },
  },
  hero: {
    badge: '1.0.0-alpha is here',
    title: 'Your connection,',
    accent: 'your server.',
    description:
      'Run your own privacy transport with Umbra’s CLI client and server. Use a real site as cover, choose TCP or QUIC for your network, and connect your apps through local SOCKS5.',
    start: 'Get started',
    explore: 'Compare options',
    footnote: 'MIT open source. Self-hosted. Alpha software.',
  },
  diagram: {
    client: 'Your device',
    transport: 'Private transport',
    internet: 'Open internet',
    cover: 'Real destination',
    authenticated: 'Authenticated',
    fallback: 'Unauthenticated → real site',
    caption: 'Your traffic uses the authenticated path; other requests go to the real site.',
  },
  facts: [
    'Real-site cover',
    'Choose for your network',
    'Connect existing clients',
    'Open source, self-hosted',
  ],
  principles: {
    eyebrow: 'For your own deployment',
    title: 'Keep control.\nKeep your tools.',
    description:
      'Choose Umbra when you want to run both endpoints and connect the apps you already use, with clear limits on what the transport protects.',
    features: [
      {
        title: 'A real site as cover',
        description:
          'Unauthenticated requests are forwarded to your configured real destination rather than receiving a proxy-specific rejection. This does not guarantee an undetectable connection.',
      },
      {
        title: 'A browser-shaped handshake',
        description:
          'Chrome profiles guide the TLS ClientHello shape, including extension order and GREASE. This follows browser handshake patterns, not a promise of an identical browser fingerprint.',
      },
      {
        title: 'No CA certificate upkeep for your node',
        description:
          'You do not need to obtain or renew a CA-issued certificate for the Umbra node. You still need keys and a reachable real TLS 1.3 site as cover.',
      },
      {
        title: 'One entry for your existing tools',
        description:
          'A local SOCKS5 entry can carry TCP and UDP over separately configured transports. Connect a Clash-style client through SOCKS5 to keep its routing rules.',
      },
    ],
  },
  start: {
    eyebrow: 'From installation to your first connection',
    title: 'Install. Configure.\nConnect your apps.',
    description:
      'Download and install a matching release asset, or optionally build from source. Generate keys, configure the server and CLI client, then point your apps to the local SOCKS5 listener on loopback.',
    link: 'Read the quick start',
    terminal: 'Build from source',
  },
  docs: {
    eyebrow: 'Documentation',
    title: 'Find the setup that fits.',
    description:
      'Install both endpoints, choose your transport settings, and compare options before committing to a deployment.',
    cards: [
      {
        title: 'Start here',
        description: 'Install Umbra and connect your first client.',
      },
      {
        title: 'Make it your own',
        description: 'Understand server, client and transport settings.',
      },
      {
        title: 'Compare mainstream options',
        description: 'Compare proxy mechanisms, deployment needs and compatibility.',
      },
    ],
  },
  cta: {
    title: 'Make your next connection your own.',
    description: 'Compare the options, check the limits, then set up Umbra.',
  },
  footer: {
    description: 'Privacy transport for an open internet.',
    project: 'Project',
    resources: 'Resources',
    legal: 'For lawful privacy protection and access to the open internet.',
    license: 'Released under the MIT license.',
  },
  download: {
    eyebrow: 'Your next connection starts here',
    title: 'Get Umbra.',
    description:
      'One command-line binary includes client and server modes. Choose an available build for your platform or build it yourself.',
    alpha: 'Alpha release · review the setup and security notes before use.',
    platform: 'Platform',
    architecture: 'Architecture',
    releases: 'View release assets',
    source: 'Prefer to build it yourself?',
    sourceDescription:
      'Building from source is optional when a suitable release asset is available. Use the same version for your client and server.',
    verify: 'Know what you download',
    verifyDescription:
      'Download from the official release listing. Check the assets and verification information provided for that release; this page does not imply that every target has a published binary.',
    requirements:
      'Building from source requires the Rust toolchain pinned by this repository (currently 1.96.1).',
  },
  protocol: {
    eyebrow: 'Mechanisms & choices',
    title: 'Understand the options.\nChoose your setup.',
    description:
      'See what real-site cover, Vision and transport selection mean for your connections. Umbra is a self-hosted CLI client and server, not a managed proxy service.',
    steps: [
      {
        title: 'Cover with a real destination',
        description:
          'REALITY authentication separates your traffic from unauthenticated requests, which are forwarded to the configured real site. You need keys and a reachable TLS 1.3 destination, but no CA-issued certificate for the node. Cover does not guarantee invisibility.',
      },
      {
        title: 'Reduce double encryption where it applies',
        description:
          'TCP mux shares a connection across streams. With mux=false, Vision removes redundant outer encryption only after authentication and only for eligible inner TLS 1.3 traffic. Non-TLS traffic stays encrypted.',
      },
      {
        title: 'Choose TCP or QUIC for your network',
        description:
          'Transport selection is explicit, not automatic failover. QUIC needs open UDP and a reachable real QUIC fallback destination. It does not guarantee higher speed or the absence of all head-of-line blocking.',
      },
    ],
    implementation: 'How to choose among mainstream options',
    implementationDescription:
      'Umbra and Xray are software platforms; VLESS, VMess, Trojan and Shadowsocks are protocols, while REALITY and Vision are mechanisms. Implementation and configuration determine behavior. There are no like-for-like competitor benchmarks here to support a speed ranking. The short version: Umbra is worth choosing when you want cover, both transport paths and SOCKS5 shipped as one configured pair you administer; the others win when you need their ecosystems.',
    strengthsLabel: 'Strengths',
    limitsLabel: 'Trade-offs',
    layers: [
      {
        title: 'Umbra',
        description:
          'An integrated, self-hosted alpha: REALITY-style real-site cover, TCP mux/Vision, QUIC and SOCKS5 ship as one client and server pair you administer end to end.',
        strengths: [
          'One endpoint covers both paths: TCP Vision and QUIC UDP sit behind a single local SOCKS5 node, so clients configure one hop.',
          'No certificate paperwork: identity keys and temporary certificate binding replace obtaining and renewing a public CA certificate.',
        ],
        limits: [
          'Alpha software and CLI only today; it does not import VLESS, VMess or Trojan nodes.',
          'Protocol changes between releases mean upgrading both endpoints together.',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          'The closest alternative: REALITY and Vision are available here too, so the choice is about packaging and workflow, not exclusive technology.',
        strengths: [
          'Mature multiprotocol platform with rich routing, many ready-made clients and extensive community documentation.',
        ],
        limits: [
          'You assemble and maintain the stack yourself: core config, transports, routing rules and matching clients.',
          'Shared mechanisms do not make it interoperable with Umbra.',
        ],
      },
      {
        title: 'VMess',
        description:
          'An AEAD proxy protocol worth considering when your clients already support it. TLS and WebSocket are additional deployment choices, not prerequisites for encryption.',
        strengths: [
          'Very wide client support across platforms, including older and low-power devices.',
        ],
        limits: [
          'The protocol encrypts but does not camouflage: cover depends entirely on the transport you add on top.',
          'Legacy non-AEAD modes are deprecated; pin clients that implement AEAD.',
        ],
      },
      {
        title: 'Trojan',
        description:
          'A TLS-based proxy protocol for those who prefer a conventional TLS deployment; fallback behavior depends on the implementation and configuration.',
        strengths: [
          'Real TLS handshake with documented fallback behavior and a design that has been stable for years.',
        ],
        limits: [
          'Typical setups maintain a domain and renew a publicly trusted certificate.',
          'UDP rides inside TLS over TCP, so UDP timing follows the TCP path.',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          'A lightweight encrypted proxy for simpler deployments; browser impersonation and real-site cover are not built into the base AEAD or 2022 protocols.',
        strengths: [
          'Minimal moving parts: keys and a matching client, no domain or certificate required.',
        ],
        limits: [
          'Base protocols provide encryption, not camouflage; assess plugins separately if you need cover.',
          'A TCP-only SIP003 plugin must not be treated as UDP camouflage.',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          'A QUIC-focused solution with its own congestion-control design; consider it where UDP is reliably reachable.',
        strengths: [
          'Unreliable datagram UDP path designed for lossy networks, with congestion control tuned for harsh conditions.',
        ],
        limits: [
          'Blocked or restricted UDP removes its main advantage, and its design is not a guarantee of speed on your network.',
          'TCP still travels as QUIC streams, so loss can stall streams like any reliable transport.',
        ],
      },
    ],
    caveat:
      'Fingerprint limits: chrome-latest currently follows the historical Chrome 150 profile. Chrome 153 capture evidence does not establish full fingerprint equivalence. ML-DSA binds the temporary certificate public key; ML-KEM enters the key schedule only when a hybrid group is negotiated. Standard CLI target probing uses ring without ML-KEM support, so there is no default end-to-end post-quantum guarantee.',
  },
  security: {
    eyebrow: 'Security & responsibility',
    title: 'Trust starts\nwith clarity.',
    description:
      'Running your own transport gives you control of both endpoints. It also means protecting credentials, restricting access and understanding what cover cannot hide.',
    principles: [
      {
        title: 'Protect your credentials',
        description:
          'Keep server private keys and client credentials out of shared configs, logs and public reports. Restrict access to the files that hold them.',
      },
      {
        title: 'Keep local access local',
        description:
          'The local SOCKS5 listener has no authentication. Bind it to loopback; exposing it to other devices requires separate access controls.',
      },
      {
        title: 'Keep HTTPS end to end',
        description:
          'Use application HTTPS even when traffic travels through Umbra. Vision only removes eligible redundant outer encryption; it does not replace the application’s TLS protection.',
      },
      {
        title: 'Know the limits of cover',
        description:
          'Unauthenticated requests go to the real destination, not a proxy-specific rejection. This does not make all traffic indistinguishable or rule out detection by an observer.',
      },
    ],
    limitsTitle: 'Understand the boundaries',
    limits: [
      'Umbra is alpha software; this page is not a claim of an independent security audit.',
      'Keep application HTTPS enabled. A privacy transport does not make endpoints, browsers or destination services trustworthy.',
      'The local SOCKS5 listener has no authentication. Keep it bound to loopback unless you deliberately secure access elsewhere.',
      'Full Chrome fingerprint equivalence is not established. Network conditions and observer capabilities can affect detectability.',
      'Protect server private keys and client credentials. Deployment choices, software updates and endpoint security remain your responsibility.',
    ],
    disclosure: 'Report issues without exposing secrets.',
    disclosureDescription:
      'The source and security model are public. Review the repository’s current reporting guidance before sharing a vulnerability; do not publish credentials or sensitive deployment details.',
    source: 'Open the repository',
  },
  changelog: {
    eyebrow: 'Release updates',
    title: 'What changes for you.',
    description:
      'Changes to connection handling and the details you need when upgrading your deployment.',
    prerelease: 'Prerelease',
    heading: 'Updates for shared connections and UDP',
    summary:
      'This alpha updates how shared connections and UDP traffic are handled. The single-instance TCP/Vision + QUIC UDP setup remains available; these changes are not a promise of higher speed on every network.',
    changes: [
      'Supported hardware can provide cryptographic acceleration, while reused TLS cipher contexts avoid repeated setup.',
      'When TCP connections are shared with mux, ready streams are scheduled with larger startup windows kept within memory budgets.',
      'QUIC receives traffic in batches and advances UDP independently; BBR remains the default congestion control.',
      'Optional numeric diagnostics help inspect transport behavior without reporting destination addresses or credentials.',
    ],
    upgrade:
      'Upgrade both endpoints for adaptive mux. Review the performance configuration and release verification before deploying.',
    read: 'Read the release notes',
  },
};

const zhHans: MarketingCopy = {
  nav: {
    docs: '文档',
    protocol: '协议',
    download: '下载',
    security: '安全',
    changelog: '更新日志',
    github: 'GitHub',
  },
  ui: {
    language: '语言',
    theme: '切换明暗主题',
    menu: '打开导航',
    skip: '跳至正文',
    copy: '复制命令',
    copied: '已复制',
    copyFailed: '请选中下方命令并复制',
    close: '关闭',
  },
  pages: {
    home: {
      title: '你的连接，由你自建。',
      description:
        '用 Umbra 命令行客户端与服务端自建隐私传输。以真实站点作掩护，按网络选择 TCP 或 QUIC，通过本地 SOCKS5 接入现有应用。',
    },
    download: {
      title: '获取 Umbra',
      description:
        '按实际发布附件选择 macOS、Linux 或 Windows 版本，也可从源码构建客户端和服务端。',
    },
    protocol: {
      title: '看懂机制，选对方案',
      description:
        '了解 Umbra 的真实站点掩护、Vision 与 TCP/QUIC 选择，再对比主流代理方案的适用条件与取舍。',
    },
    security: {
      title: '信任，始于透明',
      description: '了解 Umbra 的安全模型、自建部署责任与当前 alpha 版本的限制。',
    },
    changelog: {
      title: '每次更新，与你何关',
      description: '查看 Umbra 版本发布、连接处理变化与两端升级说明。',
    },
  },
  hero: {
    badge: '1.0.0-alpha 现已发布',
    title: '你的连接，',
    accent: '由你自建。',
    description:
      '用 Umbra 命令行客户端与服务端，建立自己掌控的隐私传输。以真实站点作掩护，按网络选择 TCP 或 QUIC，通过本地 SOCKS5 接入你惯用的应用。',
    start: '快速开始',
    explore: '方案对比',
    footnote: 'MIT 开源 · 自主部署 · Alpha 阶段',
  },
  diagram: {
    client: '你的设备',
    transport: '隐私传输',
    internet: '开放互联网',
    cover: '真实目标站点',
    authenticated: '通过认证',
    fallback: '未认证 → 真实站点',
    caption: '你的流量走认证通路，其他请求转发至真实站点。',
  },
  facts: ['真实站点掩护', '按网络选择', '接入现有客户端', '开源自主部署'],
  principles: {
    eyebrow: '为自主部署而选',
    title: '连接自己掌控，\n工具继续沿用。',
    description:
      '如果你愿意自行管理两端，又希望继续使用现有应用，Umbra 提供一条边界明确的隐私传输路径。',
    features: [
      {
        title: '让真实站点作掩护',
        description:
          '未认证请求会转发到配置的真实目标站点，而不是收到代理特有的拒绝响应。这不意味着连接无法被识别。',
      },
      {
        title: '采用浏览器握手形态',
        description:
          '由 Chrome 档案驱动 TLS ClientHello 的形态，包括扩展顺序与 GREASE。参考浏览器握手行为，不等于承诺指纹完全一致。',
      },
      {
        title: '少一项 CA 证书运维',
        description:
          '无需为 Umbra 节点自行申请或续期 CA 签发的证书。仍需准备密钥，并选择可达的真实 TLS 1.3 站点作掩护。',
      },
      {
        title: '一个入口，沿用现有工具',
        description:
          '本地 SOCKS5 入口可将 TCP 与 UDP 交给分别配置的传输路径。Clash 类客户端可通过 SOCKS5 接入，保留原有分流规则。',
      },
    ],
  },
  start: {
    eyebrow: '从安装，到第一次连接',
    title: '安装、配置，\n再接入你的应用。',
    description:
      '下载安装适合平台的发布附件，也可选择从源码构建。生成密钥，配置服务端与命令行客户端，再将应用指向绑定回环地址的本地 SOCKS5 入口。',
    link: '阅读快速开始',
    terminal: '从源码构建',
  },
  docs: {
    eyebrow: '文档中心',
    title: '找到适合你的配置。',
    description:
      '从两端安装到传输选择，先了解使用条件，再决定如何部署。',
    cards: [
      {
        title: '从这里开始',
        description: '安装 Umbra，连接你的第一个客户端。',
      },
      { title: '按需配置', description: '理解服务端、客户端与传输选项。' },
      {
        title: '主流方案对比',
        description: '比较代理机制、部署需求与兼容性，了解各自取舍。',
      },
    ],
  },
  cta: {
    title: '下一次连接，由你掌控。',
    description: '比较方案，确认边界，再开始部署 Umbra。',
  },
  footer: {
    description: '面向开放互联网的隐私传输。',
    project: '项目',
    resources: '资源',
    legal: '用于合法的隐私保护与开放互联网访问。',
    license: '基于 MIT 许可证发布。',
  },
  download: {
    eyebrow: '下一次连接，从这里开始',
    title: '获取 Umbra。',
    description:
      '一个命令行程序，包含客户端与服务端模式。选择适合平台的已发布文件，或自行构建。',
    alpha: 'Alpha 预发布版本 · 使用前请阅读配置与安全说明。',
    platform: '平台',
    architecture: '架构',
    releases: '查看发布文件',
    source: '想从源码构建？',
    sourceDescription:
      '有适用的发布附件时，源码构建并非必需。客户端与服务端请使用同一版本。',
    verify: '了解你下载的文件',
    verifyDescription:
      '请从官方版本列表下载，并核对该版本提供的文件与验证信息。本页面不表示每一种目标平台都已有发布文件。',
    requirements: '源码构建需要仓库固定的 Rust 工具链（当前为 1.96.1）。',
  },
  protocol: {
    eyebrow: '机制与选型',
    title: '看懂机制，\n选对方案。',
    description:
      '了解真实站点掩护、Vision 与传输选择如何影响你的连接。Umbra 是需要自建的命令行客户端与服务端，不是托管代理服务。',
    steps: [
      {
        title: '以真实目标站点作掩护',
        description:
          'REALITY 认证区分你的流量与未认证请求，后者会转发至配置的真实站点。你需要密钥与可达的 TLS 1.3 目标站点，但无需为节点申请 CA 证书。掩护不保证不可识别。',
      },
      {
        title: '有条件地减少双重加密',
        description:
          'TCP mux 让多个流复用一条连接。设置 mux=false 后，Vision 仅在认证完成且内层 TLS 1.3 流量符合条件时，省掉外层重复加密；非 TLS 流量继续加密。',
      },
      {
        title: '按网络选择 TCP 或 QUIC',
        description:
          '传输方式需要显式选择，不会自动故障切换。QUIC 需要 UDP 开放及可达的真实 QUIC 回落目标，不保证更快，也不保证消除所有队头阻塞。',
      },
    ],
    implementation: '与主流方案怎么选',
    implementationDescription:
      'Umbra、Xray 是软件平台；VLESS、VMess、Trojan、Shadowsocks 是协议，REALITY 与 Vision 则是机制。具体行为由实现与配置决定。没有竞品同条件性能测试，因此这里不做速度排名。一句话概括：想要掩护、双传输路径与 SOCKS5 打包成一套自行管理的完整方案时，Umbra 值得选择；需要其他生态时，它们的方案更合适。',
    strengthsLabel: '优势',
    limitsLabel: '局限',
    layers: [
      {
        title: 'Umbra',
        description:
          '集成 REALITY、TCP mux/Vision、QUIC 与 SOCKS5 的自建 alpha 方案，客户端与服务端成对交付、由你端到端管理。',
        strengths: [
          '一个端点承载两条路径：TCP Vision 与 QUIC UDP 共用同一个本地 SOCKS5 节点，客户端只需配置一个入口。',
          '无需证书手续：身份密钥与临时证书绑定代替公网 CA 证书的申请和续期。',
        ],
        limits: [
          '目前是 alpha 阶段的纯命令行工具，不兼容导入 VLESS、VMess 或 Trojan 节点。',
          '版本间协议可能变化，升级时两端需要一起更新。',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          '最接近的同类组合，同样可以使用 REALITY 与 Vision；选择的关键在于打包与工作流，而非独有技术。',
        strengths: [
          '成熟的多协议平台，路由能力强，现成客户端多，社区文档丰富。',
        ],
        limits: [
          '整套装栈需要自行组装和维护：核心配置、传输层、路由规则与配套客户端。',
          '采用相近机制不代表能与 Umbra 互通。',
        ],
      },
      {
        title: 'VMess',
        description:
          '采用 AEAD 的代理协议，已有客户端支持时值得考虑。TLS 与 WebSocket 属于额外部署选择，不是具备加密能力的前提。',
        strengths: [
          '客户端覆盖面极广，跨平台，旧设备和低配设备也有支持。',
        ],
        limits: [
          '协议只负责加密、不负责伪装：掩护完全取决于你额外搭配的传输层。',
          '旧的非 AEAD 模式已弃用，请固定使用实现 AEAD 的客户端版本。',
        ],
      },
      {
        title: 'Trojan',
        description:
          '基于 TLS 的代理协议，适合偏好常规 TLS 部署的用户；是否回落及如何回落，取决于实现与配置。',
        strengths: [
          '真实的 TLS 握手，回落行为有文档可依，设计多年稳定。',
        ],
        limits: [
          '常见部署需要维护域名并续期公网受信证书。',
          'UDP 封装在 TLS 之上的 TCP 内，UDP 时延表现跟随 TCP 路径。',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          '面向简洁部署的轻量加密代理；浏览器形态伪装和真实站点掩护并非 AEAD 或 2022 基础协议自带能力。',
        strengths: [
          '组成简单：密钥加配套客户端即可，无需域名或证书。',
        ],
        limits: [
          '基础协议提供加密而非伪装；需要掩护时应另行评估插件。',
          '仅支持 TCP 的 SIP003 插件不能当作 UDP 伪装。',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          '以 QUIC 为重点、采用自有拥塞控制设计；适合 UDP 稳定可达的环境。',
        strengths: [
          '面向高丢包网络的不可靠数据报 UDP 路径，拥塞控制为恶劣条件调优。',
        ],
        limits: [
          'UDP 被封锁或受限时失去主要优势，设计也不能保证在你的网络上一定更快。',
          'TCP 仍以 QUIC 流承载，丢包时同样会像可靠传输一样被阻塞。',
        ],
      },
    ],
    caveat:
      '指纹边界：chrome-latest 当前仍跟随历史 Chrome 150 档案，Chrome 153 抓包证据不代表完整指纹一致性。ML-DSA 用于绑定临时证书公钥；ML-KEM 仅在协商混合组后进入密钥调度。标准 CLI 目标探测采用不支持 ML-KEM 的 ring，因此不承诺默认全链路抗量子。',
  },
  security: {
    eyebrow: '安全与使用责任',
    title: '信任，\n始于透明。',
    description:
      '自建传输让你掌控两端，也需要你保护凭证、限制访问，并了解站点掩护无法隐藏什么。',
    principles: [
      {
        title: '保护密钥与凭证',
        description:
          '不要把服务端私钥或客户端凭证放进共享配置、日志和公开报告。限制他人访问存放这些信息的文件。',
      },
      {
        title: '本地入口只向本地开放',
        description:
          '本地 SOCKS5 监听没有认证，请绑定回环地址。若要向其他设备开放，必须另行设置访问控制。',
      },
      {
        title: '始终保留应用层 HTTPS',
        description:
          '即使流量经过 Umbra，也应启用应用层 HTTPS。Vision 只减少符合条件的外层重复加密，不替代应用自身的 TLS 保护。',
      },
      {
        title: '认清探测抵抗的边界',
        description:
          '未认证请求会转发至真实站点，而非收到代理特有的拒绝响应。这并不意味着所有流量都无法区分，也不能排除被观察者识别。',
      },
    ],
    limitsTitle: '理解安全边界',
    limits: [
      'Umbra 仍是 alpha 软件；本页内容不代表已完成独立安全审计。',
      '请保持应用层 HTTPS。隐私传输无法保证终端、浏览器或目标服务可信。',
      '本地 SOCKS5 监听不提供认证。除非已采取额外访问控制，否则请绑定回环地址。',
      '尚未证明与 Chrome 指纹完全一致。网络环境和观察者能力都会影响可探测性。',
      '保护服务端私钥与客户端凭证。部署选择、软件更新与端点安全仍需自行管理。',
    ],
    disclosure: '报告问题，不暴露秘密。',
    disclosureDescription:
      '源码与安全模型公开可查。分享漏洞前请查阅仓库当前的报告指引，不要公开凭证或敏感部署细节。',
    source: '查看源码仓库',
  },
  changelog: {
    eyebrow: '版本更新',
    title: '每次更新，与你何关。',
    description: '了解连接处理的变化，以及升级自建部署时需要注意的事项。',
    prerelease: '预发布',
    heading: '共享连接与 UDP 的处理更新',
    summary:
      '本次 alpha 调整共享连接与 UDP 流量的处理，继续支持单实例 TCP/Vision + QUIC UDP 配置。这些变化不代表在所有网络上都会提速。',
    changes: [
      '支持的硬件可提供密码学加速，TLS 密码上下文复用可避免重复初始化。',
      '通过 mux 共享 TCP 连接时，按就绪流调度，并在内存预算内使用更大的启动窗口。',
      'QUIC 批量接收流量，UDP 处理独立推进；默认拥塞控制仍为 BBR。',
      '可选的数值诊断帮助了解传输状态，不报告目标地址或凭证。',
    ],
    upgrade:
      '使用自适应 mux 时，请同步升级两端。部署前请阅读性能配置与版本验证记录。',
    read: '阅读版本说明',
  },
};

const zhHant: MarketingCopy = {
  nav: {
    docs: '文件',
    protocol: '協定',
    download: '下載',
    security: '安全',
    changelog: '更新日誌',
    github: 'GitHub',
  },
  ui: {
    language: '語言',
    theme: '切換明暗主題',
    menu: '開啟導覽',
    skip: '跳至正文',
    copy: '複製指令',
    copied: '已複製',
    copyFailed: '請選取下方指令並複製',
    close: '關閉',
  },
  pages: {
    home: {
      title: '你的連線，由你自建。',
      description:
        '用 Umbra 命令列用戶端與伺服器自建隱私傳輸。以真實網站作掩護，依網路選擇 TCP 或 QUIC，透過本機 SOCKS5 接入現有應用程式。',
    },
    download: {
      title: '取得 Umbra',
      description:
        '依實際發布附件選擇 macOS、Linux 或 Windows 版本，也可從原始碼建置用戶端與伺服器。',
    },
    protocol: {
      title: '看懂機制，選對方案',
      description:
        '了解 Umbra 的真實網站掩護、Vision 與 TCP/QUIC 選擇，再比較主流代理方案的適用條件與取捨。',
    },
    security: {
      title: '信任，始於透明',
      description: '了解 Umbra 的安全模型、自建部署責任與目前 alpha 版本的限制。',
    },
    changelog: {
      title: '每次更新，帶來哪些改變',
      description: '查看 Umbra 版本發布、連線處理變化與兩端升級說明。',
    },
  },
  hero: {
    badge: '1.0.0-alpha 現已發布',
    title: '你的連線，',
    accent: '由你自建。',
    description:
      '用 Umbra 命令列用戶端與伺服器，建立自己掌控的隱私傳輸。以真實網站作掩護，依網路選擇 TCP 或 QUIC，透過本機 SOCKS5 接入你慣用的應用程式。',
    start: '快速入門',
    explore: '方案比較',
    footnote: 'MIT 開源 · 自主部署 · Alpha 階段',
  },
  diagram: {
    client: '你的裝置',
    transport: '隱私傳輸',
    internet: '開放網際網路',
    cover: '真實目的網站',
    authenticated: '通過驗證',
    fallback: '未驗證 → 真實網站',
    caption: '你的流量走驗證通道，其他請求轉送至真實網站。',
  },
  facts: ['真實網站掩護', '依網路選擇', '接入現有用戶端', '開源自主部署'],
  principles: {
    eyebrow: '為自主部署而選',
    title: '連線自己掌控，\n工具繼續沿用。',
    description:
      '如果你願意自行管理兩端，又希望繼續使用現有應用程式，Umbra 提供一條邊界明確的隱私傳輸路徑。',
    features: [
      {
        title: '讓真實網站作掩護',
        description:
          '未驗證請求會轉送至設定的真實目的網站，而不是收到代理特有的拒絕回應。這不代表連線無法被識別。',
      },
      {
        title: '採用瀏覽器交握形態',
        description:
          '由 Chrome 設定檔驅動 TLS ClientHello 的形態，包括擴充順序與 GREASE。參考瀏覽器交握行為，不等於承諾指紋完全一致。',
      },
      {
        title: '少一項 CA 憑證維護',
        description:
          '無需為 Umbra 節點自行申請或更新 CA 簽發的憑證。仍需準備金鑰，並選擇可連線的真實 TLS 1.3 網站作掩護。',
      },
      {
        title: '一個入口，沿用現有工具',
        description:
          '本機 SOCKS5 入口可將 TCP 與 UDP 交給分別設定的傳輸路徑。Clash 類用戶端可透過 SOCKS5 接入，保留原有分流規則。',
      },
    ],
  },
  start: {
    eyebrow: '從安裝，到第一次連線',
    title: '安裝、設定，\n再接入你的應用程式。',
    description:
      '下載並安裝適合平台的發布附件，也可選擇從原始碼建置。產生金鑰，設定伺服器與命令列用戶端，再將應用程式指向綁定回送位址的本機 SOCKS5 入口。',
    link: '閱讀快速入門',
    terminal: '從原始碼建置',
  },
  docs: {
    eyebrow: '文件中心',
    title: '找到適合你的設定。',
    description:
      '從兩端安裝到傳輸選擇，先了解使用條件，再決定如何部署。',
    cards: [
      {
        title: '從這裡開始',
        description: '安裝 Umbra，連接你的第一個用戶端。',
      },
      { title: '依需求設定', description: '理解伺服器、用戶端與傳輸選項。' },
      {
        title: '主流方案比較',
        description: '比較代理機制、部署需求與相容性，了解各自取捨。',
      },
    ],
  },
  cta: {
    title: '下一次連線，由你掌控。',
    description: '比較方案，確認邊界，再開始部署 Umbra。',
  },
  footer: {
    description: '面向開放網際網路的隱私傳輸。',
    project: '專案',
    resources: '資源',
    legal: '用於合法的隱私保護與開放網際網路存取。',
    license: '以 MIT 授權條款發布。',
  },
  download: {
    eyebrow: '下一次連線，從這裡開始',
    title: '取得 Umbra。',
    description:
      '一個命令列程式，包含用戶端與伺服器模式。選擇適合平台的已發布檔案，或自行建置。',
    alpha: 'Alpha 預發行版本 · 使用前請閱讀設定與安全說明。',
    platform: '平台',
    architecture: '架構',
    releases: '查看發布檔案',
    source: '想從原始碼建置？',
    sourceDescription:
      '有適用的發布附件時，不一定要從原始碼建置。用戶端與伺服器請使用同一版本。',
    verify: '了解你下載的檔案',
    verifyDescription:
      '請從官方版本清單下載，並核對該版本提供的檔案與驗證資訊。本頁面不表示每種目標平台都已有發布檔案。',
    requirements: '原始碼建置需要儲存庫固定的 Rust 工具鏈（目前為 1.96.1）。',
  },
  protocol: {
    eyebrow: '機制與選型',
    title: '看懂機制，\n選對方案。',
    description:
      '了解真實網站掩護、Vision 與傳輸選擇如何影響你的連線。Umbra 是需要自建的命令列用戶端與伺服器，不是代管代理服務。',
    steps: [
      {
        title: '以真實目的網站作掩護',
        description:
          'REALITY 驗證區分你的流量與未驗證請求，後者會轉送至設定的真實網站。你需要金鑰與可連線的 TLS 1.3 目的網站，但無需為節點申請 CA 憑證。掩護不保證無法被識別。',
      },
      {
        title: '有條件地減少雙重加密',
        description:
          'TCP mux 讓多個串流共用一條連線。設定 mux=false 後，Vision 僅在驗證完成且內層 TLS 1.3 流量符合條件時，省去外層重複加密；非 TLS 流量繼續加密。',
      },
      {
        title: '依網路選擇 TCP 或 QUIC',
        description:
          '傳輸方式需要明確選擇，不會自動容錯切換。QUIC 需要 UDP 開放及可連線的真實 QUIC 回退目標，不保證更快，也不保證消除所有隊頭阻塞。',
      },
    ],
    implementation: '與主流方案怎麼選',
    implementationDescription:
      'Umbra、Xray 是軟體平台；VLESS、VMess、Trojan、Shadowsocks 是協定，REALITY 與 Vision 則是機制。具體行為由實作與設定決定。沒有競品同條件效能測試，因此這裡不做速度排名。一句話概括：想要掩護、雙傳輸路徑與 SOCKS5 打包成一套自行管理的完整方案時，Umbra 值得選擇；需要其他生態系時，它們的方案更合適。',
    strengthsLabel: '優勢',
    limitsLabel: '侷限',
    layers: [
      {
        title: 'Umbra',
        description:
          '整合 REALITY、TCP mux/Vision、QUIC 與 SOCKS5 的自建 alpha 方案，用戶端與伺服器成對交付、由你端到端管理。',
        strengths: [
          '一個端點承載兩條路徑：TCP Vision 與 QUIC UDP 共用同一個本機 SOCKS5 節點，用戶端只需設定一個入口。',
          '無需憑證手續：身分金鑰與臨時憑證綁定代替公網 CA 憑證的申請與續期。',
        ],
        limits: [
          '目前是 alpha 階段的純命令列工具，不相容匯入 VLESS、VMess 或 Trojan 節點。',
          '版本間協定可能變動，升級時兩端需要一起更新。',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          '最接近的同類組合，同樣可以使用 REALITY 與 Vision；選擇的關鍵在於打包與工作流程，而非獨有技術。',
        strengths: [
          '成熟的多協定平台，路由能力強，現成用戶端多，社群文件豐富。',
        ],
        limits: [
          '整套堆疊需要自行組裝與維護：核心設定、傳輸層、路由規則與配套用戶端。',
          '採用相近機制不代表能與 Umbra 互通。',
        ],
      },
      {
        title: 'VMess',
        description:
          '採用 AEAD 的代理協定，已有用戶端支援時值得考慮。TLS 與 WebSocket 屬於額外部署選擇，不是具備加密能力的前提。',
        strengths: [
          '用戶端涵蓋面極廣，跨平台，舊裝置與低階裝置也有支援。',
        ],
        limits: [
          '協定只負責加密、不負責偽裝：掩護完全取決於你額外搭配的傳輸層。',
          '舊的非 AEAD 模式已棄用，請固定使用實作 AEAD 的用戶端版本。',
        ],
      },
      {
        title: 'Trojan',
        description:
          '基於 TLS 的代理協定，適合偏好常規 TLS 部署的使用者；是否回退及如何回退，取決於實作與設定。',
        strengths: [
          '真實的 TLS 交握，回退行為有文件可循，設計多年穩定。',
        ],
        limits: [
          '常見部署需要維護網域並續期公網受信憑證。',
          'UDP 封裝在 TLS 之上的 TCP 內，UDP 延遲表現跟隨 TCP 路徑。',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          '面向簡潔部署的輕量加密代理；瀏覽器形態偽裝與真實網站掩護並非 AEAD 或 2022 基礎協定內建能力。',
        strengths: [
          '組成簡單：金鑰加配套用戶端即可，無需網域或憑證。',
        ],
        limits: [
          '基礎協定提供加密而非偽裝；需要掩護時應另外評估外掛程式。',
          '僅支援 TCP 的 SIP003 外掛程式不能當作 UDP 偽裝。',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          '以 QUIC 為重點、採用自有壅塞控制設計；適合 UDP 穩定可達的環境。',
        strengths: [
          '面向高丟包網路的不可靠資料包 UDP 路徑，壅塞控制為惡劣條件調校。',
        ],
        limits: [
          'UDP 被封鎖或受限時失去主要優勢，設計也不能保證在你的網路上一定更快。',
          'TCP 仍以 QUIC 串流承載，丟包時同樣會像可靠傳輸一樣被阻塞。',
        ],
      },
    ],
    caveat:
      '指紋邊界：chrome-latest 目前仍採用歷史 Chrome 150 設定檔，Chrome 153 封包擷取證據不代表完整指紋一致性。ML-DSA 用於綁定臨時憑證公鑰；ML-KEM 僅在協商混合群組後進入金鑰排程。標準 CLI 目標探測採用不支援 ML-KEM 的 ring，因此不承諾預設端到端抗量子。',
  },
  security: {
    eyebrow: '安全與使用責任',
    title: '信任，\n始於透明。',
    description:
      '自建傳輸讓你掌控兩端，也需要你保護憑證、限制存取，並了解網站掩護無法隱藏什麼。',
    principles: [
      {
        title: '保護金鑰與憑證',
        description:
          '不要把伺服器私鑰或用戶端憑證放進共用設定、日誌和公開報告。限制他人存取存放這些資訊的檔案。',
      },
      {
        title: '本機入口只向本機開放',
        description:
          '本機 SOCKS5 監聽沒有驗證，請綁定回送位址。若要向其他裝置開放，必須另外設定存取控制。',
      },
      {
        title: '始終保留應用層 HTTPS',
        description:
          '即使流量經過 Umbra，也應啟用應用層 HTTPS。Vision 只減少符合條件的外層重複加密，不取代應用程式本身的 TLS 保護。',
      },
      {
        title: '認清探測抵抗的邊界',
        description:
          '未驗證請求會轉送至真實網站，而非收到代理特有的拒絕回應。這不代表所有流量都無法區分，也不能排除被觀察者識別。',
      },
    ],
    limitsTitle: '理解安全邊界',
    limits: [
      'Umbra 仍是 alpha 軟體；本頁內容不代表已完成獨立安全稽核。',
      '請保持應用層 HTTPS。隱私傳輸無法保證終端、瀏覽器或目的服務可信。',
      '本機 SOCKS5 監聽不提供驗證。除非已採取額外存取控制，否則請綁定回送位址。',
      '尚未證明與 Chrome 指紋完全一致。網路環境及觀察者能力都會影響可探測性。',
      '保護伺服器私鑰與用戶端憑證。部署選擇、軟體更新與端點安全仍需自行管理。',
    ],
    disclosure: '回報問題，不暴露秘密。',
    disclosureDescription:
      '原始碼與安全模型公開可查。分享漏洞前請查閱儲存庫目前的回報指引，不要公開憑證或敏感部署細節。',
    source: '查看原始碼儲存庫',
  },
  changelog: {
    eyebrow: '版本更新',
    title: '每次更新，帶來哪些改變。',
    description: '了解連線處理的變化，以及升級自建部署時需要注意的事項。',
    prerelease: '預發行',
    heading: '共用連線與 UDP 的處理更新',
    summary:
      '本次 alpha 調整共用連線與 UDP 流量的處理，繼續支援單一執行個體 TCP/Vision + QUIC UDP 設定。這些變化不代表在所有網路上都會加速。',
    changes: [
      '支援的硬體可提供密碼學加速，TLS 密碼上下文重複使用可避免重複初始化。',
      '透過 mux 共用 TCP 連線時，依就緒串流排程，並在記憶體預算內使用更大的啟動視窗。',
      'QUIC 批次接收流量，UDP 處理獨立推進；預設壅塞控制仍為 BBR。',
      '可選的數值診斷協助了解傳輸狀態，不回報目的位址或憑證。',
    ],
    upgrade:
      '使用自適應 mux 時，請同步升級兩端。部署前請閱讀效能設定與版本驗證紀錄。',
    read: '閱讀版本說明',
  },
};

const fr: MarketingCopy = {
  nav: {
    docs: 'Documentation',
    protocol: 'Protocole',
    download: 'Télécharger',
    security: 'Sécurité',
    changelog: 'Versions',
    github: 'GitHub',
  },
  ui: {
    language: 'Langue',
    theme: 'Changer de thème',
    menu: 'Ouvrir la navigation',
    skip: 'Aller au contenu',
    copy: 'Copier les commandes',
    copied: 'Copié',
    copyFailed: 'Sélectionnez et copiez les commandes ci-dessous',
    close: 'Fermer',
  },
  pages: {
    home: {
      title: 'Votre connexion. Votre serveur.',
      description:
        'Auto-hébergez votre transport confidentiel avec le client et le serveur en ligne de commande Umbra. Site réel en couverture, TCP ou QUIC et SOCKS5 local pour vos applications.',
    },
    download: {
      title: 'Obtenir Umbra',
      description:
        'Choisissez une version pour macOS, Linux ou Windows parmi les fichiers effectivement publiés, ou compilez le client et le serveur depuis les sources.',
    },
    protocol: {
      title: 'Comprendre les options pour bien choisir',
      description:
        'Découvrez la couverture par un site réel, Vision et les choix TCP/QUIC d’Umbra, puis comparez les compromis avec les autres solutions proxy.',
    },
    security: {
      title: 'La confiance commence par la clarté',
      description:
        'Comprenez le modèle de sécurité, vos responsabilités de déploiement et les limites de la version alpha.',
    },
    changelog: {
      title: 'Ce qui change pour vous',
      description:
        'Suivez les versions d’Umbra, les évolutions du traitement des connexions et les consignes de mise à niveau des deux extrémités.',
    },
  },
  hero: {
    badge: 'La version 1.0.0-alpha est disponible',
    title: 'Votre connexion,',
    accent: 'votre serveur.',
    description:
      'Hébergez votre propre transport confidentiel avec le client et le serveur en ligne de commande Umbra. Utilisez un site réel comme couverture, choisissez TCP ou QUIC selon votre réseau et connectez vos applications via SOCKS5 en local.',
    start: 'Bien démarrer',
    explore: 'Comparer les solutions',
    footnote: 'Code ouvert sous licence MIT. Auto-hébergé. Version alpha.',
  },
  diagram: {
    client: 'Votre appareil',
    transport: 'Transport privé',
    internet: 'Internet ouvert',
    cover: 'Destination réelle',
    authenticated: 'Authentifié',
    fallback: 'Sans authentification → site réel',
    caption: 'Votre trafic emprunte le chemin authentifié ; les autres requêtes rejoignent le site réel.',
  },
  facts: [
    'Couverture par un site réel',
    'Au choix selon le réseau',
    'Vos clients existants',
    'Code ouvert, auto-hébergé',
  ],
  principles: {
    eyebrow: 'Pour votre propre déploiement',
    title: 'Gardez le contrôle.\nGardez vos outils.',
    description:
      'Choisissez Umbra si vous souhaitez gérer les deux extrémités tout en conservant vos applications, avec des limites de protection clairement définies.',
    features: [
      {
        title: 'Un site réel comme couverture',
        description:
          'Les requêtes non authentifiées sont transmises à la destination réelle configurée, sans rejet propre à un proxy. Cela ne garantit pas une connexion indétectable.',
      },
      {
        title: 'Une négociation inspirée du navigateur',
        description:
          'Les profils Chrome guident la forme du TLS ClientHello, notamment l’ordre des extensions et GREASE. Suivre ces modèles ne garantit pas une empreinte identique à celle du navigateur.',
      },
      {
        title: 'Pas de certificat d’AC à renouveler pour le nœud',
        description:
          'Vous n’avez pas à obtenir ni à renouveler un certificat d’autorité de certification pour le nœud Umbra. Des clés et un site réel TLS 1.3 joignable restent nécessaires.',
      },
      {
        title: 'Une entrée pour vos outils existants',
        description:
          'Une entrée SOCKS5 locale peut acheminer TCP et UDP par des transports configurés séparément. Raccordez un client de type Clash via SOCKS5 pour conserver ses règles de routage.',
      },
    ],
  },
  start: {
    eyebrow: 'De l’installation à la première connexion',
    title: 'Installez. Configurez.\nConnectez vos applications.',
    description:
      'Téléchargez et installez un fichier adapté, ou compilez depuis les sources si vous le préférez. Générez les clés, configurez le serveur et le client en ligne de commande, puis raccordez vos applications à SOCKS5 sur l’interface de bouclage.',
    link: 'Lire le guide de démarrage',
    terminal: 'Compiler depuis les sources',
  },
  docs: {
    eyebrow: 'Documentation',
    title: 'Trouvez la configuration qui vous convient.',
    description:
      'Installez les deux extrémités, choisissez vos transports et comparez les options avant de déployer.',
    cards: [
      {
        title: 'Commencer ici',
        description: 'Installez Umbra et connectez votre premier client.',
      },
      {
        title: 'Adapter la configuration',
        description:
          'Comprenez les réglages du serveur, du client et du transport.',
      },
      {
        title: 'Comparer les principales solutions',
        description: 'Comparez les mécanismes proxy, les besoins de déploiement et la compatibilité.',
      },
    ],
  },
  cta: {
    title: 'Prenez en main votre prochaine connexion.',
    description:
      'Comparez les solutions, vérifiez leurs limites, puis installez Umbra.',
  },
  footer: {
    description: 'Un transport confidentiel pour un Internet ouvert.',
    project: 'Projet',
    resources: 'Ressources',
    legal:
      'Pour la protection licite de la vie privée et l’accès à l’Internet ouvert.',
    license: 'Publié sous licence MIT.',
  },
  download: {
    eyebrow: 'Votre prochaine connexion commence ici',
    title: 'Obtenir Umbra.',
    description:
      'Un seul programme en ligne de commande propose les modes client et serveur. Choisissez un fichier publié pour votre plateforme ou compilez-le vous-même.',
    alpha:
      'Version alpha · consultez les notes de configuration et de sécurité avant utilisation.',
    platform: 'Plateforme',
    architecture: 'Architecture',
    releases: 'Voir les fichiers publiés',
    source: 'Vous préférez compiler ?',
    sourceDescription:
      'La compilation est facultative si un fichier publié convient à votre plateforme. Utilisez la même version pour le client et le serveur.',
    verify: 'Vérifiez ce que vous téléchargez',
    verifyDescription:
      'Utilisez la liste officielle des versions. Vérifiez les fichiers et les informations de validation de la version choisie ; cette page ne garantit pas la disponibilité d’un binaire pour chaque cible.',
    requirements:
      'La compilation nécessite la version de Rust fixée par le dépôt (actuellement 1.96.1).',
  },
  protocol: {
    eyebrow: 'Mécanismes et choix',
    title: 'Comprendre les options.\nChoisir sa configuration.',
    description:
      'Découvrez ce que la couverture par un site réel, Vision et le choix du transport changent pour vos connexions. Umbra est un client et un serveur en ligne de commande à héberger vous-même, pas un service proxy géré.',
    steps: [
      {
        title: 'Un site réel comme couverture',
        description:
          'L’authentification REALITY distingue votre trafic des requêtes non authentifiées, transmises au site réel configuré. Il faut des clés et une destination TLS 1.3 joignable, mais pas de certificat d’AC pour le nœud. Cette couverture ne garantit pas l’invisibilité.',
      },
      {
        title: 'Réduire le double chiffrement sous conditions',
        description:
          'Le mux TCP partage une connexion entre plusieurs flux. Avec mux=false, Vision retire le chiffrement externe redondant uniquement après authentification et pour du trafic TLS 1.3 interne éligible. Le trafic non TLS reste chiffré.',
      },
      {
        title: 'Choisir TCP ou QUIC selon le réseau',
        description:
          'Le transport se choisit explicitement, sans basculement automatique. QUIC exige un accès UDP ouvert et une destination de repli QUIC réelle et joignable. Il ne garantit ni plus de vitesse ni l’absence de tout blocage en tête de file.',
      },
    ],
    implementation: 'Comment choisir parmi les principales solutions',
    implementationDescription:
      'Umbra et Xray sont des plateformes logicielles ; VLESS, VMess, Trojan et Shadowsocks sont des protocoles, tandis que REALITY et Vision sont des mécanismes. Le comportement dépend de l’implémentation et de la configuration. Aucune mesure comparative à conditions égales ne justifie ici un classement de vitesse. En résumé : Umbra mérite votre choix quand vous voulez la couverture, les deux voies de transport et SOCKS5 livrés en un couple configuré que vous administrez ; les autres l’emportent quand vous avez besoin de leurs écosystèmes.',
    strengthsLabel: 'Points forts',
    limitsLabel: 'Limites',
    layers: [
      {
        title: 'Umbra',
        description:
          'Une solution alpha auto-hébergée intégrant REALITY, TCP mux/Vision, QUIC et SOCKS5 : client et serveur livrés en couple, administrés de bout en bout par vos soins.',
        strengths: [
          'Un seul point d’accès pour les deux voies : TCP Vision et UDP QUIC passent par le même nœud SOCKS5 local ; les clients ne configurent qu’un seul point d’entrée.',
          'Aucune démarche de certificat : les clés d’identité et la liaison au certificat temporaire remplacent la demande et le renouvellement d’un certificat CA public.',
        ],
        limits: [
          'Alpha en ligne de commande uniquement ; aucun import de nœuds VLESS, VMess ou Trojan.',
          'Le protocole peut changer entre versions : mettez à jour les deux extrémités ensemble.',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          'L’alternative la plus proche : REALITY et Vision y sont aussi disponibles ; le choix porte sur l’emballage et le flux de travail, pas sur une technologie exclusive.',
        strengths: [
          'Plateforme multiprotocole mature : routage riche, nombreux clients prêts à l’emploi et documentation communautaire étendue.',
        ],
        limits: [
          'Vous assemblez et maintenez la pile vous-même : configuration centrale, couches de transport, règles de routage et clients assortis.',
          'Des mécanismes communs ne rendent pas les deux interopérables.',
        ],
      },
      {
        title: 'VMess',
        description:
          'Un protocole proxy AEAD à envisager si vos clients le prennent déjà en charge. TLS et WebSocket sont des choix de déploiement supplémentaires, pas des prérequis au chiffrement.',
        strengths: [
          'Prise en charge client très large, sur toutes les plateformes, y compris les appareils anciens ou modestes.',
        ],
        limits: [
          'Le protocole chiffre sans camoufler : la couverture dépend entièrement de la couche de transport que vous ajoutez.',
          'Les anciens modes non AEAD sont déconseillés ; ciblez des clients qui implémentent AEAD.',
        ],
      },
      {
        title: 'Trojan',
        description:
          'Un protocole proxy fondé sur TLS, pour ceux qui préfèrent un déploiement TLS classique ; le repli dépend de l’implémentation et de la configuration.',
        strengths: [
          'Véritable poignée de main TLS, repli documenté, conception stable depuis des années.',
        ],
        limits: [
          'Les installations courantes demandent de gérer un domaine et de renouveler un certificat public de confiance.',
          'L’UDP voyage dans TCP sous TLS : sa latence suit le chemin TCP.',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          'Un proxy chiffré léger pour les déploiements simples ; l’imitation d’un navigateur et la couverture par un site réel ne font pas partie des protocoles de base AEAD ou 2022.',
        strengths: [
          'Composants minimaux : des clés et un client assorti, sans domaine ni certificat.',
        ],
        limits: [
          'Les protocoles de base chiffrent sans camoufler ; évaluez les plugins séparément si vous voulez une couverture.',
          'Un plugin SIP003 limité à TCP ne doit pas être pris pour un camouflage UDP.',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          'Une solution centrée sur QUIC avec sa propre conception du contrôle de congestion ; à envisager si UDP est accessible de façon fiable.',
        strengths: [
          'Voie UDP en datagrammes non fiables conçue pour les réseaux à fortes pertes, avec un contrôle de congestion taillé pour les conditions difficiles.',
        ],
        limits: [
          'UDP bloqué ou restreint supprime son principal atout, et sa conception ne garantit pas une vitesse supérieure sur votre réseau.',
          'Le TCP reste porté par des flux QUIC : les pertes peuvent bloquer les flux comme dans tout transport fiable.',
        ],
      },
    ],
    caveat:
      'Limites d’empreinte : chrome-latest suit toujours le profil historique de Chrome 150. Les captures de Chrome 153 ne démontrent pas une équivalence complète d’empreinte. ML-DSA lie la clé publique du certificat temporaire ; ML-KEM intervient dans la dérivation des clés uniquement si un groupe hybride est négocié. La sonde de destination du CLI standard utilise ring sans prise en charge de ML-KEM : aucune garantie post-quantique de bout en bout par défaut.',
  },
  security: {
    eyebrow: 'Sécurité et responsabilités',
    title: 'La confiance commence\npar la clarté.',
    description:
      'Héberger votre transport vous donne le contrôle des deux extrémités. Cela implique aussi de protéger les identifiants, de limiter les accès et de comprendre ce que la couverture ne masque pas.',
    principles: [
      {
        title: 'Protéger les clés et les identifiants',
        description:
          'Ne placez pas les clés privées du serveur ni les identifiants clients dans des configurations partagées, des journaux ou des rapports publics. Limitez l’accès aux fichiers qui les contiennent.',
      },
      {
        title: 'Réserver l’accès local à votre appareil',
        description:
          'L’écoute SOCKS5 locale n’a pas d’authentification. Liez-la à l’interface de bouclage ; l’ouvrir à d’autres appareils exige des contrôles d’accès distincts.',
      },
      {
        title: 'Conserver HTTPS de bout en bout',
        description:
          'Gardez HTTPS dans vos applications, même avec Umbra. Vision ne retire que le chiffrement externe redondant lorsque les conditions sont réunies ; il ne remplace pas le TLS de l’application.',
      },
      {
        title: 'Connaître les limites de la couverture',
        description:
          'Les requêtes non authentifiées rejoignent le site réel, sans rejet propre à un proxy. Cela ne rend pas tout le trafic indiscernable et n’exclut pas sa détection par un observateur.',
      },
    ],
    limitsTitle: 'Comprendre les limites',
    limits: [
      'Umbra est un logiciel alpha ; cette page n’atteste pas d’un audit de sécurité indépendant.',
      'Conservez HTTPS dans les applications. Un transport confidentiel ne rend pas fiables les appareils, navigateurs ou services de destination.',
      'L’écoute SOCKS5 locale ne propose pas d’authentification. Gardez-la sur l’interface de bouclage sans autre contrôle d’accès explicite.',
      'L’équivalence complète avec les empreintes Chrome n’est pas établie. La détectabilité dépend du réseau et de l’observateur.',
      'Protégez les clés privées du serveur et les identifiants clients. Déploiement, mises à jour et sécurité des terminaux restent à votre charge.',
    ],
    disclosure: 'Signaler les problèmes sans exposer les secrets.',
    disclosureDescription:
      'Le code et le modèle de sécurité sont publics. Consultez les consignes actuelles du dépôt avant de signaler une vulnérabilité ; ne publiez ni identifiants ni détails de déploiement sensibles.',
    source: 'Ouvrir le dépôt',
  },
  changelog: {
    eyebrow: 'Nouvelles versions',
    title: 'Ce qui change pour vous.',
    description:
      'Les évolutions du traitement des connexions et les points à vérifier lors de vos mises à niveau.',
    prerelease: 'Préversion',
    heading: 'Du nouveau pour les connexions partagées et UDP',
    summary:
      'Cette alpha modifie le traitement des connexions partagées et du trafic UDP. La configuration TCP/Vision + QUIC UDP dans une seule instance reste disponible ; ces changements ne promettent pas un gain de vitesse sur tous les réseaux.',
    changes: [
      'Le matériel compatible peut accélérer la cryptographie ; la réutilisation des contextes TLS évite de répéter leur initialisation.',
      'Avec des connexions TCP partagées par mux, les flux prêts sont ordonnancés avec des fenêtres initiales plus grandes, dans les limites des budgets mémoire.',
      'QUIC reçoit le trafic par lots et fait progresser UDP indépendamment ; BBR reste le contrôle de congestion par défaut.',
      'Des diagnostics numériques facultatifs aident à examiner le transport sans rapporter les adresses de destination ni les identifiants.',
    ],
    upgrade:
      'Mettez à niveau les deux extrémités pour le mux adaptatif. Lisez la configuration des performances et les vérifications avant déploiement.',
    read: 'Lire les notes de version',
  },
};

const es: MarketingCopy = {
  nav: {
    docs: 'Documentación',
    protocol: 'Protocolo',
    download: 'Descargar',
    security: 'Seguridad',
    changelog: 'Versiones',
    github: 'GitHub',
  },
  ui: {
    language: 'Idioma',
    theme: 'Cambiar tema',
    menu: 'Abrir navegación',
    skip: 'Saltar al contenido',
    copy: 'Copiar comandos',
    copied: 'Copiado',
    copyFailed: 'Selecciona y copia los comandos de abajo',
    close: 'Cerrar',
  },
  pages: {
    home: {
      title: 'Tu conexión. Tu servidor.',
      description:
        'Aloja tu propio transporte privado con el cliente y el servidor de línea de comandos de Umbra. Cobertura con un sitio real, TCP o QUIC y SOCKS5 local para tus aplicaciones.',
    },
    download: {
      title: 'Obtén Umbra',
      description:
        'Elige una versión para macOS, Linux o Windows entre los archivos publicados, o compila el cliente y el servidor desde el código fuente.',
    },
    protocol: {
      title: 'Entiende las opciones. Elige tu configuración.',
      description:
        'Conoce la cobertura con un sitio real, Vision y las opciones TCP/QUIC de Umbra, y compara sus ventajas y límites con otras soluciones proxy.',
    },
    security: {
      title: 'La confianza empieza con claridad',
      description:
        'Conoce el modelo de seguridad, tus responsabilidades de despliegue y las limitaciones de la versión alpha.',
    },
    changelog: {
      title: 'Qué cambia para ti',
      description:
        'Consulta las versiones de Umbra, los cambios en la gestión de conexiones y las indicaciones para actualizar ambos extremos.',
    },
  },
  hero: {
    badge: '1.0.0-alpha ya está disponible',
    title: 'Tu conexión,',
    accent: 'tu servidor.',
    description:
      'Aloja tu propio transporte privado con el cliente y el servidor de línea de comandos de Umbra. Usa un sitio real como cobertura, elige TCP o QUIC según tu red y conecta tus aplicaciones mediante SOCKS5 local.',
    start: 'Primeros pasos',
    explore: 'Comparar soluciones',
    footnote: 'Código abierto con licencia MIT. Alojamiento propio. Versión alpha.',
  },
  diagram: {
    client: 'Tu dispositivo',
    transport: 'Transporte privado',
    internet: 'Internet abierta',
    cover: 'Destino real',
    authenticated: 'Autenticado',
    fallback: 'Sin autenticación → sitio real',
    caption: 'Tu tráfico usa la ruta autenticada; las demás solicitudes van al sitio real.',
  },
  facts: [
    'Cobertura con un sitio real',
    'Elige según tu red',
    'Conecta tus clientes actuales',
    'Código abierto, alojamiento propio',
  ],
  principles: {
    eyebrow: 'Para tu propio despliegue',
    title: 'Conserva el control.\nY tus herramientas.',
    description:
      'Elige Umbra si quieres gestionar ambos extremos sin dejar tus aplicaciones habituales, con límites claros sobre lo que protege el transporte.',
    features: [
      {
        title: 'Un sitio real como cobertura',
        description:
          'Las solicitudes sin autenticar se reenvían al destino real configurado, sin un rechazo propio de un proxy. Esto no garantiza que la conexión sea indetectable.',
      },
      {
        title: 'Un saludo inspirado en el navegador',
        description:
          'Los perfiles de Chrome guían la forma del TLS ClientHello, incluido el orden de extensiones y GREASE. Seguir esos patrones no garantiza una huella idéntica a la del navegador.',
      },
      {
        title: 'Sin renovar certificados de CA para el nodo',
        description:
          'No necesitas obtener ni renovar un certificado emitido por una CA para el nodo Umbra. Sigues necesitando claves y un sitio real TLS 1.3 accesible como cobertura.',
      },
      {
        title: 'Una entrada para tus herramientas',
        description:
          'Una entrada SOCKS5 local puede llevar TCP y UDP por transportes configurados por separado. Conecta un cliente de tipo Clash mediante SOCKS5 para conservar sus reglas de enrutamiento.',
      },
    ],
  },
  start: {
    eyebrow: 'De la instalación a tu primera conexión',
    title: 'Instala. Configura.\nConecta tus aplicaciones.',
    description:
      'Descarga e instala un archivo publicado para tu plataforma, o compila opcionalmente desde el código fuente. Genera las claves, configura el servidor y el cliente de línea de comandos, y dirige tus aplicaciones al SOCKS5 local vinculado a la interfaz de bucle local.',
    link: 'Leer la guía rápida',
    terminal: 'Compilar desde el código fuente',
  },
  docs: {
    eyebrow: 'Documentación',
    title: 'Encuentra la configuración que necesitas.',
    description:
      'Instala ambos extremos, elige los transportes y compara las opciones antes de desplegar.',
    cards: [
      {
        title: 'Empieza aquí',
        description: 'Instala Umbra y conecta tu primer cliente.',
      },
      {
        title: 'Configúralo a tu medida',
        description:
          'Comprende los ajustes del servidor, cliente y transporte.',
      },
      {
        title: 'Compara las principales soluciones',
        description: 'Compara mecanismos proxy, requisitos de despliegue y compatibilidad.',
      },
    ],
  },
  cta: {
    title: 'Toma el control de tu próxima conexión.',
    description: 'Compara las opciones, revisa los límites y configura Umbra.',
  },
  footer: {
    description: 'Transporte de privacidad para una internet abierta.',
    project: 'Proyecto',
    resources: 'Recursos',
    legal:
      'Para la protección legal de la privacidad y el acceso a la internet abierta.',
    license: 'Publicado bajo la licencia MIT.',
  },
  download: {
    eyebrow: 'Tu próxima conexión empieza aquí',
    title: 'Obtén Umbra.',
    description:
      'Un programa de línea de comandos incluye los modos cliente y servidor. Elige un archivo publicado para tu plataforma o compílalo tú mismo.',
    alpha:
      'Versión alpha · consulta la configuración y las notas de seguridad antes de usarla.',
    platform: 'Plataforma',
    architecture: 'Arquitectura',
    releases: 'Ver archivos de versiones',
    source: '¿Prefieres compilarlo?',
    sourceDescription:
      'Compilar es opcional si hay un archivo publicado adecuado para tu plataforma. Usa la misma versión en el cliente y el servidor.',
    verify: 'Conoce lo que descargas',
    verifyDescription:
      'Descarga desde la lista oficial de versiones. Comprueba los archivos y la información de verificación de esa versión; esta página no garantiza binarios publicados para todos los destinos.',
    requirements:
      'La compilación requiere la versión de Rust fijada por el repositorio (actualmente 1.96.1).',
  },
  protocol: {
    eyebrow: 'Mecanismos y elección',
    title: 'Entiende las opciones.\nElige tu configuración.',
    description:
      'Descubre qué aportan la cobertura con un sitio real, Vision y la elección del transporte a tus conexiones. Umbra es un cliente y un servidor de línea de comandos que alojas tú, no un servicio proxy gestionado.',
    steps: [
      {
        title: 'Usa un destino real como cobertura',
        description:
          'La autenticación REALITY distingue tu tráfico de las solicitudes sin autenticar, que se reenvían al sitio real configurado. Necesitas claves y un destino TLS 1.3 accesible, pero no un certificado de CA para el nodo. La cobertura no garantiza invisibilidad.',
      },
      {
        title: 'Reduce el doble cifrado cuando corresponde',
        description:
          'El mux TCP comparte una conexión entre varios flujos. Con mux=false, Vision retira el cifrado externo redundante solo tras la autenticación y para tráfico TLS 1.3 interno que cumpla las condiciones. El tráfico no TLS sigue cifrado.',
      },
      {
        title: 'Elige TCP o QUIC según tu red',
        description:
          'El transporte se elige explícitamente, sin conmutación automática ante fallos. QUIC necesita UDP abierto y un destino QUIC real y accesible para el tráfico de cobertura. No garantiza más velocidad ni la ausencia de todo bloqueo de cabecera de línea.',
      },
    ],
    implementation: 'Cómo elegir entre las principales soluciones',
    implementationDescription:
      'Umbra y Xray son plataformas de software; VLESS, VMess, Trojan y Shadowsocks son protocolos, mientras que REALITY y Vision son mecanismos. El comportamiento depende de la implementación y la configuración. Sin pruebas comparativas en igualdad de condiciones, aquí no hay una clasificación por velocidad. En resumen: Umbra merece tu elección cuando quieres cobertura, ambas vías de transporte y SOCKS5 entregados como un par configurado que administras tú; las demás ganan cuando necesitas sus ecosistemas.',
    strengthsLabel: 'Ventajas',
    limitsLabel: 'Limitaciones',
    layers: [
      {
        title: 'Umbra',
        description:
          'Una solución alpha de alojamiento propio que integra REALITY, TCP mux/Vision, QUIC y SOCKS5: cliente y servidor se entregan como par y los administras de extremo a extremo.',
        strengths: [
          'Un único extremo cubre ambas vías: TCP Vision y UDP QUIC comparten el mismo nodo SOCKS5 local, de modo que los clientes solo configuran un punto de entrada.',
          'Sin trámites de certificados: las claves de identidad y el enlace al certificado temporal sustituyen a solicitar y renovar un certificado de CA público.',
        ],
        limits: [
          'Alpha y solo de línea de comandos por ahora; no importa nodos VLESS, VMess ni Trojan.',
          'El protocolo puede cambiar entre versiones: actualiza ambos extremos a la vez.',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          'La alternativa más cercana: REALITY y Vision también están disponibles aquí, así que la elección trata del empaquetado y el flujo de trabajo, no de una tecnología exclusiva.',
        strengths: [
          'Plataforma multiprotocolo madura, con enrutamiento rico, muchos clientes listos para usar y abundante documentación comunitaria.',
        ],
        limits: [
          'Tú mismo ensamblas y mantienes la pila: configuración principal, capas de transporte, reglas de enrutamiento y clientes a juego.',
          'Compartir mecanismos no permite la interoperabilidad con Umbra.',
        ],
      },
      {
        title: 'VMess',
        description:
          'Un protocolo proxy AEAD que conviene considerar si tus clientes ya lo admiten. TLS y WebSocket son opciones adicionales de despliegue, no requisitos para tener cifrado.',
        strengths: [
          'Compatibilidad con clientes muy amplia y multiplataforma, incluidos equipos antiguos o modestos.',
        ],
        limits: [
          'El protocolo cifra pero no camufla: la cobertura depende por completo del transporte que añadas encima.',
          'Los modos antiguos sin AEAD están obsoletos; usa clientes que implementen AEAD.',
        ],
      },
      {
        title: 'Trojan',
        description:
          'Un protocolo proxy basado en TLS para quienes prefieren un despliegue TLS convencional; el comportamiento de fallback depende de la implementación y la configuración.',
        strengths: [
          'Auténtico apretón de manos TLS con fallback documentado y un diseño estable durante años.',
        ],
        limits: [
          'Las instalaciones habituales requieren mantener un dominio y renovar un certificado público de confianza.',
          'El UDP viaja dentro de TCP bajo TLS, así que su latencia sigue la ruta TCP.',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          'Un proxy cifrado ligero para despliegues sencillos; la imitación de un navegador y la cobertura con un sitio real no vienen incluidas en los protocolos base AEAD o 2022.',
        strengths: [
          'Componentes mínimos: claves y un cliente a juego, sin dominio ni certificado.',
        ],
        limits: [
          'Los protocolos base cifran, no camuflan; evalúa los plugins por separado si necesitas cobertura.',
          'Un plugin SIP003 solo para TCP no debe tomarse por camuflaje de UDP.',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          'Una solución centrada en QUIC con su propio diseño de control de congestión; considérala si UDP es accesible de forma fiable.',
        strengths: [
          'Vía UDP con datagramas no fiables, diseñada para redes con muchas pérdidas y un control de congestión afinado para condiciones duras.',
        ],
        limits: [
          'Si UDP está bloqueado o restringido pierde su ventaja principal, y su diseño no garantiza más velocidad en tu red.',
          'El TCP sigue viajando como flujos QUIC, así que las pérdidas pueden bloquear los flujos como en cualquier transporte fiable.',
        ],
      },
    ],
    caveat:
      'Límites de la huella: chrome-latest sigue el perfil histórico de Chrome 150. Las capturas de Chrome 153 no prueban una equivalencia completa de huella. ML-DSA vincula la clave pública del certificado temporal; ML-KEM solo interviene en la derivación de claves si se negocia un grupo híbrido. La sonda de destino del CLI estándar usa ring sin soporte para ML-KEM, por lo que no hay garantía poscuántica de extremo a extremo por defecto.',
  },
  security: {
    eyebrow: 'Seguridad y responsabilidad',
    title: 'La confianza empieza\ncon claridad.',
    description:
      'Alojar tu transporte te da el control de ambos extremos. También exige proteger las credenciales, restringir el acceso y entender qué no puede ocultar la cobertura.',
    principles: [
      {
        title: 'Protege tus claves y credenciales',
        description:
          'No incluyas claves privadas del servidor ni credenciales del cliente en configuraciones compartidas, registros o informes públicos. Restringe el acceso a los archivos que las contienen.',
      },
      {
        title: 'Limita el acceso local a tu equipo',
        description:
          'El servicio SOCKS5 local no tiene autenticación. Vincúlalo a la interfaz de bucle local; exponerlo a otros dispositivos requiere controles de acceso adicionales.',
      },
      {
        title: 'Mantén HTTPS de extremo a extremo',
        description:
          'Usa HTTPS en las aplicaciones aunque el tráfico pase por Umbra. Vision solo retira el cifrado externo redundante cuando se cumplen las condiciones; no sustituye el TLS de la aplicación.',
      },
      {
        title: 'Conoce los límites de la cobertura',
        description:
          'Las solicitudes sin autenticar van al destino real, sin un rechazo propio de un proxy. Esto no hace indistinguible todo el tráfico ni impide que un observador pueda detectarlo.',
      },
    ],
    limitsTitle: 'Comprende los límites',
    limits: [
      'Umbra es software alpha; esta página no acredita una auditoría de seguridad independiente.',
      'Mantén HTTPS en las aplicaciones. Un transporte privado no convierte en fiables los dispositivos, navegadores ni servicios de destino.',
      'El servicio SOCKS5 local no tiene autenticación. Usa la interfaz de bucle local salvo que controles el acceso de otra forma.',
      'No se ha demostrado equivalencia completa con Chrome. La detectabilidad depende de la red y de las capacidades del observador.',
      'Protege las claves privadas del servidor y las credenciales del cliente. El despliegue, las actualizaciones y los dispositivos siguen siendo tu responsabilidad.',
    ],
    disclosure: 'Comunica problemas sin exponer secretos.',
    disclosureDescription:
      'El código y el modelo de seguridad son públicos. Consulta las instrucciones actuales del repositorio antes de comunicar una vulnerabilidad; no publiques credenciales ni detalles sensibles.',
    source: 'Abrir el repositorio',
  },
  changelog: {
    eyebrow: 'Novedades de cada versión',
    title: 'Qué cambia para ti.',
    description:
      'Cambios en la gestión de conexiones y detalles que debes revisar al actualizar tu despliegue.',
    prerelease: 'Versión preliminar',
    heading: 'Novedades para conexiones compartidas y UDP',
    summary:
      'Esta alpha actualiza la gestión de las conexiones compartidas y del tráfico UDP. Sigue disponible TCP/Vision + QUIC UDP en una sola instancia; estos cambios no prometen más velocidad en todas las redes.',
    changes: [
      'El hardware compatible puede acelerar la criptografía; reutilizar contextos de cifrado TLS evita repetir su inicialización.',
      'Al compartir conexiones TCP con mux, se planifican los flujos listos con ventanas iniciales mayores dentro de los presupuestos de memoria.',
      'QUIC recibe tráfico por lotes y hace avanzar UDP de forma independiente; BBR sigue siendo el control de congestión predeterminado.',
      'Los diagnósticos numéricos opcionales permiten examinar el transporte sin informar de destinos ni credenciales.',
    ],
    upgrade:
      'Actualiza ambos extremos para el mux adaptativo. Revisa la configuración de rendimiento y la verificación de la versión antes del despliegue.',
    read: 'Leer las notas de versión',
  },
};

const ja: MarketingCopy = {
  nav: {
    docs: 'ドキュメント',
    protocol: 'プロトコル',
    download: 'ダウンロード',
    security: 'セキュリティ',
    changelog: '更新履歴',
    github: 'GitHub',
  },
  ui: {
    language: '言語',
    theme: '配色テーマを切り替える',
    menu: 'ナビゲーションを開く',
    skip: '本文へ移動',
    copy: 'コマンドをコピー',
    copied: 'コピーしました',
    copyFailed: '下のコマンドを選択してコピーしてください',
    close: '閉じる',
  },
  pages: {
    home: {
      title: '自分の接続を、自分のサーバーで。',
      description:
        'Umbra の CLI クライアントとサーバーで、プライバシー通信を自分で運用。実在サイトによるカバー、TCP または QUIC、ローカル SOCKS5 でいつものアプリを接続できます。',
    },
    download: {
      title: 'Umbra を入手',
      description:
        '実際のリリース添付ファイルから macOS、Linux、Windows 向けのものを選ぶか、クライアントとサーバーをソースからビルドできます。',
    },
    protocol: {
      title: '仕組みを知り、自分に合う構成を選ぶ',
      description:
        'Umbra の実在サイトによるカバー、Vision、TCP/QUIC の選択を理解し、主なプロキシ方式との違いや利用条件を比較できます。',
    },
    security: {
      title: '信頼は、透明性から',
      description:
        'Umbra のセキュリティモデル、運用者の責任、alpha 版の制限を確認できます。',
    },
    changelog: {
      title: '更新で変わること',
      description:
        'Umbra のリリース、接続処理の変更、両端をアップグレードする際の注意点を確認できます。',
    },
  },
  hero: {
    badge: '1.0.0-alpha を公開しました',
    title: '自分の接続を、',
    accent: '自分のサーバーで。',
    description:
      'Umbra の CLI クライアントとサーバーで、プライバシー通信を自分で運用。実在サイトをカバーに使い、ネットワークに合わせて TCP または QUIC を選び、ローカル SOCKS5 からいつものアプリを接続できます。',
    start: 'はじめる',
    explore: '方式を比較する',
    footnote: 'MIT オープンソース · セルフホスト · Alpha 版',
  },
  diagram: {
    client: 'あなたの端末',
    transport: 'プライベート通信',
    internet: 'オープンなネット',
    cover: '実在の接続先',
    authenticated: '認証済み',
    fallback: '未認証 → 実在サイト',
    caption: '自分の通信は認証済みの経路へ。それ以外のリクエストは実在サイトへ転送します。',
  },
  facts: [
    '実在サイトによるカバー',
    'ネットワークに合わせて選択',
    '既存クライアントと接続',
    'オープンソースで自分で運用',
  ],
  principles: {
    eyebrow: '自分で運用するための選択',
    title: '接続は自分で管理。\nツールはそのまま。',
    description:
      '両端を自分で管理しながら、使い慣れたアプリを利用したい方に。Umbra が保護できる範囲を理解したうえで選べます。',
    features: [
      {
        title: '実在サイトをカバーに',
        description:
          '未認証のリクエストは、プロキシ特有の拒否応答ではなく、設定した実在の接続先へ転送します。接続が検知されないことを保証するものではありません。',
      },
      {
        title: 'ブラウザーに倣ったハンドシェイク',
        description:
          'Chrome プロファイルに基づき、拡張の順序や GREASE を含む TLS ClientHello を構成します。ブラウザーのパターンを参考にしますが、指紋の完全一致は保証しません。',
      },
      {
        title: 'ノード用 CA 証明書の管理は不要',
        description:
          'Umbra ノード用に CA 発行証明書を取得・更新する必要はありません。ただし、鍵と、カバーに使う到達可能な実在 TLS 1.3 サイトは必要です。',
      },
      {
        title: 'ひとつの入口で、いつものツールを',
        description:
          'ローカル SOCKS5 から TCP と UDP を、それぞれ設定した通信経路へ振り分けられます。Clash 系クライアントを SOCKS5 経由で接続すれば、そのルーティングルールを維持できます。',
      },
    ],
  },
  start: {
    eyebrow: 'インストールから、最初の接続へ',
    title: 'インストール、設定、\nアプリの接続。',
    description:
      '対応するリリースファイルをダウンロードしてインストールします。ソースからビルドする方法も選べます。鍵を生成してサーバーと CLI クライアントを設定し、ループバックにバインドしたローカル SOCKS5 をアプリの接続先に指定してください。',
    link: 'クイックスタートを読む',
    terminal: 'ソースからビルド',
  },
  docs: {
    eyebrow: 'ドキュメント',
    title: '自分に合った構成を見つける。',
    description:
      '両端のインストール、通信方式の設定、ほかの選択肢との比較。導入前に必要な条件を確認できます。',
    cards: [
      {
        title: 'ここからはじめる',
        description: 'Umbra をインストールし、最初のクライアントを接続。',
      },
      {
        title: '自分に合った設定',
        description: 'サーバー、クライアント、通信の設定を理解。',
      },
      {
        title: '主なプロキシ方式を比較',
        description: '仕組み、導入に必要な条件、互換性とそれぞれの制限を比較。',
      },
    ],
  },
  cta: {
    title: '次の接続は、自分で管理。',
    description: '方式を比較し、制限を確認してから、Umbra を導入しましょう。',
  },
  footer: {
    description: 'オープンなインターネットのためのプライバシー通信。',
    project: 'プロジェクト',
    resources: 'リソース',
    legal:
      '適法なプライバシー保護とオープンなインターネットへのアクセスのために。',
    license: 'MIT ライセンスで公開。',
  },
  download: {
    eyebrow: '次の接続は、ここから',
    title: 'Umbra を入手。',
    description:
      'ひとつのコマンドラインプログラムにクライアントとサーバーのモードを搭載。対応する公開済みファイルを選ぶか、自分でビルドできます。',
    alpha:
      'Alpha プレリリース · 使用前に設定とセキュリティの説明をご確認ください。',
    platform: 'プラットフォーム',
    architecture: 'アーキテクチャ',
    releases: 'リリースファイルを見る',
    source: '自分でビルドしますか？',
    sourceDescription:
      '対応するリリースファイルがあれば、ソースからのビルドは任意です。クライアントとサーバーには同じバージョンを使ってください。',
    verify: 'ダウンロードするものを確かめる',
    verifyDescription:
      '公式リリース一覧をご利用ください。各版のファイルと検証情報を確認してください。このページは全ターゲットのバイナリ公開を保証しません。',
    requirements:
      'ビルドにはリポジトリで固定された Rust ツールチェーン（現在 1.96.1）が必要です。',
  },
  protocol: {
    eyebrow: '仕組みと選び方',
    title: '仕組みを知り、\n自分に合う構成を。',
    description:
      '実在サイトによるカバー、Vision、通信方式の選択が接続にどう関わるかを確認できます。Umbra は自分で運用する CLI クライアントとサーバーであり、運用代行型のプロキシサービスではありません。',
    steps: [
      {
        title: '実在の接続先をカバーにする',
        description:
          'REALITY 認証で自分の通信を区別し、未認証のリクエストは設定した実在サイトへ転送します。鍵と到達可能な TLS 1.3 サイトは必要ですが、ノード用 CA 証明書は不要です。カバーは検知されないことを保証しません。',
      },
      {
        title: '条件を満たす通信の二重暗号化を減らす',
        description:
          'TCP mux は複数のストリームで接続を共有します。mux=false の場合、Vision は認証後、条件を満たす内側の TLS 1.3 通信に限り、重複する外側の暗号化を省きます。非 TLS 通信の暗号化は継続します。',
      },
      {
        title: 'ネットワークに合わせて TCP か QUIC を選ぶ',
        description:
          '通信方式は明示的に選択し、自動フェイルオーバーは行いません。QUIC には UDP の疎通と、到達可能な実在の QUIC フォールバック先が必要です。高速化や、あらゆるヘッドオブラインブロッキングの解消を保証するものではありません。',
      },
    ],
    implementation: '主な方式と、どう選び分けるか',
    implementationDescription:
      'Umbra と Xray はソフトウェアプラットフォーム、VLESS・VMess・Trojan・Shadowsocks はプロトコル、REALITY と Vision は仕組みです。実際の動作は実装と設定で変わります。同条件の競合比較測定がないため、速度の順位付けはしません。ひとことで言えば、カバーと二つの転送経路と SOCKS5 を、自分で管理する一組の構成としてまとめて受け取りたいなら Umbra が向いており、各種エコシステムが必要なら他の選択肢が向いています。',
    strengthsLabel: '長所',
    limitsLabel: '制約',
    layers: [
      {
        title: 'Umbra',
        description:
          'REALITY、TCP mux/Vision、QUIC、SOCKS5 を統合したセルフホスト型の alpha です。クライアントとサーバーが一組として提供され、両端を自分で管理します。',
        strengths: [
          '一つのエンドポイントで両経路を賄えます。TCP Vision と QUIC UDP が同一のローカル SOCKS5 ノードの背後にあり、クライアントの設定は一箇所だけで済みます。',
          '証明書の手続きが不要です。アイデンティティ鍵と一時証明書のバインドにより、公開 CA 証明書の取得と更新が不要になります。',
        ],
        limits: [
          '現時点では alpha の CUI 専用で、VLESS・VMess・Trojan ノードの取り込みには対応していません。',
          'リリース間でプロトコルが変わる可能性があるため、更新は両端を同時に行います。',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          '最も近い選択肢です。REALITY と Vision はこちらでも使えるため、選択のポイントは独自技術ではなく梱包とワークフローにあります。',
        strengths: [
          '成熟したマルチプロトコルプラットフォームで、柔軟なルーティング、すぐに使えるクライアント、充実したコミュニティ文書があります。',
        ],
        limits: [
          'スタック全体を自分で組み立てて維持する必要があります。本体設定、トランスポート層、ルーティング規則、対応クライアントまで含めてです。',
          '共通の仕組みを使っていても Umbra と相互接続はできません。',
        ],
      },
      {
        title: 'VMess',
        description:
          'AEAD を使うプロキシプロトコルで、既存クライアントが対応している場合の選択肢です。TLS や WebSocket は追加の構成要素であり、暗号化の必須条件ではありません。',
        strengths: [
          'クライアントの対応範囲が非常に広く、古い機器や低スペック機でも動かせます。',
        ],
        limits: [
          'プロトコルは暗号化のみを担い、偽装は行いません。カバーの可否は上乗せしたトランスポート層次第です。',
          '旧式の非 AEAD モードは非推奨です。AEAD を実装したクライアントに絞ってください。',
        ],
      },
      {
        title: 'Trojan',
        description:
          '一般的な TLS 構成で運用したい方向けの、TLS ベースのプロキシプロトコルです。フォールバックの動作は実装と設定によって異なります。',
        strengths: [
          '本物の TLS ハンドシェイクと文書化されたフォールバック動作を備え、設計が長年安定しています。',
        ],
        limits: [
          'よくある構成ではドメインの維持と公的な信頼された証明書の更新が必要です。',
          'UDP は TLS の下の TCP 内に載るため、UDP の遅延は TCP 経路に律されます。',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          'シンプルな構成に適した軽量な暗号化プロキシです。ブラウザーの模倣や実在サイトによるカバーは、AEAD・2022 の基本プロトコルには含まれません。',
        strengths: [
          '構成要素が最小で済みます。鍵と対応クライアントがあればよく、ドメインも証明書も不要です。',
        ],
        limits: [
          '基本プロトコルは暗号化のみで、偽装は行いません。カバーが必要ならプラグインを別途評価してください。',
          'TCP 専用の SIP003 プラグインを UDP の偽装と見なしてはいけません。',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          'QUIC を中心とし、独自の輻輳制御設計を持つ方式です。UDP が安定して通る環境で検討できます。',
        strengths: [
          '高損失ネットワーク向けに設計された非信頼データグラムの UDP 経路を持ち、輻輳制御は過酷な条件に合わせて調整されています。',
        ],
        limits: [
          'UDP が遮断・制限されると主な強みを失い、設計だけでは利用中のネットワークで速くなる保証もありません。',
          'TCP は今も QUIC ストリームで運ばれるため、損失時には信頼型転送と同じくストリームが滞り得ます。',
        ],
      },
    ],
    caveat:
      '指紋の制限：chrome-latest は現在も過去の Chrome 150 プロファイルを使用します。Chrome 153 のキャプチャは指紋の完全一致を示しません。ML-DSA は一時証明書の公開鍵を結び付け、ML-KEM はハイブリッドグループをネゴシエートした場合のみ鍵スケジュールに入ります。標準 CLI の接続先プローブには ML-KEM 非対応の ring を使うため、既定で通信経路全体の耐量子性を保証するものではありません。',
  },
  security: {
    eyebrow: 'セキュリティと運用者の責任',
    title: '信頼は、\n透明性から。',
    description:
      '自分で通信を運用すれば、両端を管理できます。同時に、認証情報の保護、アクセス制限、カバーで隠せない範囲の理解も必要です。',
    principles: [
      {
        title: '鍵と認証情報を守る',
        description:
          'サーバー秘密鍵やクライアント認証情報を、共有設定、ログ、公開報告に含めないでください。保存先のファイルへのアクセスも制限してください。',
      },
      {
        title: 'ローカルの入口は端末内に限定',
        description:
          'ローカル SOCKS5 リスナーには認証がありません。ループバックにバインドし、ほかの端末に公開する場合は別途アクセス制御を設けてください。',
      },
      {
        title: 'アプリの HTTPS を維持する',
        description:
          'Umbra 経由でもアプリの HTTPS を有効にしてください。Vision が省くのは条件を満たす重複した外側の暗号化だけで、アプリ自身の TLS を置き換えるものではありません。',
      },
      {
        title: 'カバーの限界を知る',
        description:
          '未認証のリクエストはプロキシ特有の拒否応答ではなく、実在サイトへ転送します。ただし、すべての通信が区別不能になるわけではなく、観測者による検知の可能性は残ります。',
      },
    ],
    limitsTitle: '境界を理解する',
    limits: [
      'Umbra は alpha ソフトウェアです。このページは独立したセキュリティ監査の実施を示すものではありません。',
      'アプリケーションの HTTPS を有効にしてください。プライバシー通信は端末、ブラウザー、接続先サービスの信頼性を保証しません。',
      'ローカル SOCKS5 に認証はありません。別途アクセス制御を行わない限り、ループバックにバインドしてください。',
      'Chrome 指紋との完全一致は確認されていません。検知可能性はネットワークと観測者の能力に左右されます。',
      'サーバー秘密鍵とクライアント認証情報を保護してください。運用、更新、端末の安全性は利用者が管理する必要があります。',
    ],
    disclosure: '秘密を公開せずに問題を報告する。',
    disclosureDescription:
      'ソースとセキュリティモデルは公開されています。脆弱性を共有する前にリポジトリの最新の報告方針を確認し、認証情報や機密の運用情報を公開しないでください。',
    source: 'リポジトリを見る',
  },
  changelog: {
    eyebrow: 'リリースの更新情報',
    title: '更新で変わること。',
    description: '接続処理の変更と、自分の環境をアップグレードする際の確認事項。',
    prerelease: 'プレリリース',
    heading: '接続共有と UDP 処理の更新',
    summary:
      'この alpha では共有接続と UDP 通信の処理を更新しました。単一インスタンスの TCP/Vision + QUIC UDP 構成は引き続き利用できます。すべてのネットワークでの高速化を約束するものではありません。',
    changes: [
      '対応ハードウェアの暗号アクセラレーションを利用でき、TLS 暗号コンテキストの再利用で繰り返しの初期化を避けます。',
      'mux で TCP 接続を共有する際、準備できたストリームを処理し、メモリ予算内でより大きな初期ウィンドウを使います。',
      'QUIC はまとめて受信し、UDP 処理は独立して進行します。既定の輻輳制御は引き続き BBR です。',
      '任意の数値診断で通信状態を確認できます。接続先アドレスや認証情報は報告しません。',
    ],
    upgrade:
      '適応型 mux には両端の更新が必要です。運用前に性能設定とリリースの検証情報を確認してください。',
    read: 'リリースノートを読む',
  },
};

const ca: MarketingCopy = {
  nav: {
    docs: 'Documentació',
    protocol: 'Protocol',
    download: 'Baixa',
    security: 'Seguretat',
    changelog: 'Versions',
    github: 'GitHub',
  },
  ui: {
    language: 'Llengua',
    theme: 'Canvia el tema',
    menu: 'Obre la navegació',
    skip: 'Ves al contingut',
    copy: 'Copia les ordres',
    copied: 'Copiat',
    copyFailed: 'Selecciona i copia les ordres de sota',
    close: 'Tanca',
  },
  pages: {
    home: {
      title: 'La teva connexió. El teu servidor.',
      description:
        'Allotja el teu transport privat amb el client i el servidor de línia d’ordres d’Umbra. Cobertura amb un lloc real, TCP o QUIC i SOCKS5 local per a les teves aplicacions.',
    },
    download: {
      title: 'Aconsegueix Umbra',
      description:
        'Tria una versió per a macOS, Linux o Windows entre els fitxers publicats, o compila el client i el servidor des del codi font.',
    },
    protocol: {
      title: 'Entén les opcions. Tria la configuració.',
      description:
        'Coneix la cobertura amb un lloc real, Vision i les opcions TCP/QUIC d’Umbra, i compara’n els avantatges i els límits amb altres solucions de servidor intermediari.',
    },
    security: {
      title: 'La confiança comença amb claredat',
      description:
        'Coneix el model de seguretat, les teves responsabilitats de desplegament i les limitacions de la versió alfa.',
    },
    changelog: {
      title: 'Què canvia per a tu',
      description:
        'Segueix les versions d’Umbra, els canvis en la gestió de connexions i les indicacions per actualitzar tots dos extrems.',
    },
  },
  hero: {
    badge: 'Ja és aquí la versió 1.0.0-alpha',
    title: 'La teva connexió,',
    accent: 'el teu servidor.',
    description:
      'Allotja el teu transport privat amb el client i el servidor de línia d’ordres d’Umbra. Fes servir un lloc real com a cobertura, tria TCP o QUIC segons la xarxa i connecta les teves aplicacions mitjançant SOCKS5 local.',
    start: 'Primers passos',
    explore: 'Compara les solucions',
    footnote: 'Codi obert amb llicència MIT. Allotjament propi. Versió alfa.',
  },
  diagram: {
    client: 'El teu dispositiu',
    transport: 'Transport privat',
    internet: 'Internet oberta',
    cover: 'Destinació real',
    authenticated: 'Autenticat',
    fallback: 'Sense autenticació → lloc real',
    caption: 'El teu trànsit segueix el camí autenticat; la resta de peticions van al lloc real.',
  },
  facts: [
    'Cobertura amb un lloc real',
    'Tria segons la xarxa',
    'Connecta els clients actuals',
    'Codi obert, allotjament propi',
  ],
  principles: {
    eyebrow: 'Per al teu propi desplegament',
    title: 'Conserva el control.\nI les teves eines.',
    description:
      'Tria Umbra si vols gestionar tots dos extrems sense deixar les aplicacions habituals, amb límits clars sobre què protegeix el transport.',
    features: [
      {
        title: 'Un lloc real com a cobertura',
        description:
          'Les peticions no autenticades es reenvien a la destinació real configurada, sense un rebuig propi d’un intermediari. Això no garanteix que la connexió sigui indetectable.',
      },
      {
        title: 'Una negociació inspirada en el navegador',
        description:
          'Els perfils de Chrome guien la forma del TLS ClientHello, inclosos l’ordre d’extensions i GREASE. Seguir aquests patrons no garanteix una empremta idèntica a la del navegador.',
      },
      {
        title: 'Sense renovar certificats d’AC per al node',
        description:
          'No cal obtenir ni renovar un certificat emès per una autoritat de certificació per al node Umbra. Encara necessites claus i un lloc real TLS 1.3 accessible com a cobertura.',
      },
      {
        title: 'Una entrada per a les teves eines',
        description:
          'Una entrada SOCKS5 local pot portar TCP i UDP per transports configurats per separat. Connecta un client de tipus Clash mitjançant SOCKS5 per conservar-ne les regles d’encaminament.',
      },
    ],
  },
  start: {
    eyebrow: 'De la instal·lació a la primera connexió',
    title: 'Instal·la. Configura.\nConnecta les aplicacions.',
    description:
      'Baixa i instal·la un fitxer publicat per a la teva plataforma, o compila opcionalment des del codi font. Genera les claus, configura el servidor i el client de línia d’ordres, i dirigeix les aplicacions al SOCKS5 local vinculat a la interfície de bucle local.',
    link: 'Llegeix la guia ràpida',
    terminal: 'Compila des del codi font',
  },
  docs: {
    eyebrow: 'Documentació',
    title: 'Troba la configuració que et convé.',
    description:
      'Instal·la tots dos extrems, tria els transports i compara les opcions abans de desplegar.',
    cards: [
      {
        title: 'Comença aquí',
        description: 'Instal·la Umbra i connecta el primer client.',
      },
      {
        title: 'Configura’l al teu gust',
        description:
          'Entén els paràmetres del servidor, del client i del transport.',
      },
      {
        title: 'Compara les solucions principals',
        description: 'Compara mecanismes de proxy, requisits de desplegament i compatibilitat.',
      },
    ],
  },
  cta: {
    title: 'Pren el control de la pròxima connexió.',
    description: 'Compara les opcions, revisa els límits i configura Umbra.',
  },
  footer: {
    description: 'Transport de privacitat per a una internet oberta.',
    project: 'Projecte',
    resources: 'Recursos',
    legal:
      'Per a la protecció legal de la privacitat i l’accés a la internet oberta.',
    license: 'Publicat sota la llicència MIT.',
  },
  download: {
    eyebrow: 'La pròxima connexió comença aquí',
    title: 'Aconsegueix Umbra.',
    description:
      'Un programa de línia d’ordres inclou els modes client i servidor. Tria un fitxer publicat per a la teva plataforma o compila’l tu mateix.',
    alpha:
      'Versió alfa · consulta la configuració i les notes de seguretat abans d’utilitzar-la.',
    platform: 'Plataforma',
    architecture: 'Arquitectura',
    releases: 'Veure els fitxers publicats',
    source: 'Prefereixes compilar-lo?',
    sourceDescription:
      'Compilar és opcional si hi ha un fitxer publicat adequat per a la teva plataforma. Fes servir la mateixa versió al client i al servidor.',
    verify: 'Coneix el que baixes',
    verifyDescription:
      'Baixa’l des de la llista oficial de versions. Comprova els fitxers i la informació de verificació de la versió; aquesta pàgina no garanteix binaris publicats per a totes les plataformes.',
    requirements:
      'La compilació requereix la versió de Rust fixada pel repositori (actualment 1.96.1).',
  },
  protocol: {
    eyebrow: 'Mecanismes i elecció',
    title: 'Entén les opcions.\nTria la configuració.',
    description:
      'Descobreix què aporten la cobertura amb un lloc real, Vision i l’elecció del transport a les teves connexions. Umbra és un client i un servidor de línia d’ordres que allotges tu, no un servei de proxy gestionat.',
    steps: [
      {
        title: 'Fes servir una destinació real com a cobertura',
        description:
          'L’autenticació REALITY distingeix el teu trànsit de les peticions no autenticades, que es reenvien al lloc real configurat. Calen claus i una destinació TLS 1.3 accessible, però no un certificat d’AC per al node. La cobertura no garanteix invisibilitat.',
      },
      {
        title: 'Redueix el doble xifratge quan correspon',
        description:
          'El mux TCP comparteix una connexió entre diversos fluxos. Amb mux=false, Vision retira el xifratge extern redundant només després de l’autenticació i per a trànsit TLS 1.3 intern que compleixi les condicions. El trànsit no TLS continua xifrat.',
      },
      {
        title: 'Tria TCP o QUIC segons la xarxa',
        description:
          'El transport es tria explícitament, sense commutació automàtica en cas de fallada. QUIC necessita UDP obert i una destinació QUIC real i accessible per al trànsit de cobertura. No garanteix més velocitat ni l’absència de tot bloqueig de cap de línia.',
      },
    ],
    implementation: 'Com triar entre les solucions principals',
    implementationDescription:
      'Umbra i Xray són plataformes de programari; VLESS, VMess, Trojan i Shadowsocks són protocols, mentre que REALITY i Vision són mecanismes. El comportament depèn de la implementació i la configuració. Sense proves comparatives en igualtat de condicions, aquí no hi ha cap classificació per velocitat. En resum: Umbra val la pena quan vols la cobertura, les dues vies de transport i SOCKS5 lliurats com a parella configurada que administres tu; les altres guanyen quan necessites els seus ecosistemes.',
    strengthsLabel: 'Avantatges',
    limitsLabel: 'Limitacions',
    layers: [
      {
        title: 'Umbra',
        description:
          'Una solució alfa d’allotjament propi que integra REALITY, TCP mux/Vision, QUIC i SOCKS5: client i servidor es lliuren com a parella i els administres d’extrem a extrem.',
        strengths: [
          'Un sol extrem cobreix les dues vies: TCP Vision i UDP QUIC comparteixen el mateix node SOCKS5 local, de manera que els clients només configuren un punt d’entrada.',
          'Sense tràmits de certificats: les claus d’identitat i la vinculació al certificat temporal substitueixen sol·licitar i renovar un certificat de CA públic.',
        ],
        limits: [
          'Alfa i només de línia d’ordres per ara; no importa nodes VLESS, VMess ni Trojan.',
          'El protocol pot canviar entre versions: actualitza tots dos extrems alhora.',
        ],
      },
      {
        title: 'Xray + VLESS + REALITY',
        description:
          'L’alternativa més propera: REALITY i Vision també hi són disponibles, així que l’elecció tracta de l’empaquetatge i el flux de treball, no d’una tecnologia exclusiva.',
        strengths: [
          'Plataforma multiprotocol madura, amb encaminament ric, molts clients llestos per usar i documentació comunitària extensa.',
        ],
        limits: [
          'Tu mateix muntes i mantens la pila: configuració principal, capes de transport, regles d’encaminament i clients a joc.',
          'Compartir mecanismes no permet la interoperabilitat amb Umbra.',
        ],
      },
      {
        title: 'VMess',
        description:
          'Un protocol de proxy AEAD que convé considerar si els teus clients ja l’admeten. TLS i WebSocket són opcions addicionals de desplegament, no requisits per tenir xifratge.',
        strengths: [
          'Compatibilitat amb clients molt àmplia i multiplataforma, inclosos equips antics o modestos.',
        ],
        limits: [
          'El protocol xifra però no camufla: la cobertura depèn del transport que afegeixis a sobre.',
          'Els modes antics sense AEAD estan obsolets; fes servir clients que implementin AEAD.',
        ],
      },
      {
        title: 'Trojan',
        description:
          'Un protocol de proxy basat en TLS per a qui prefereix un desplegament TLS convencional; el comportament de retorn depèn de la implementació i la configuració.',
        strengths: [
          'Autèntica estreta de mans TLS amb retorn documentat i un disseny estable durant anys.',
        ],
        limits: [
          'Les instal·lacions habituals requereixen mantenir un domini i renovar un certificat públic de confiança.',
          'L’UDP viatja dins de TCP sota TLS, així que la seva latència segueix la ruta TCP.',
        ],
      },
      {
        title: 'Shadowsocks',
        description:
          'Un intermediari xifrat lleuger per a desplegaments senzills; la imitació d’un navegador i la cobertura amb un lloc real no venen incloses en els protocols base AEAD o 2022.',
        strengths: [
          'Components mínims: claus i un client a joc, sense domini ni certificat.',
        ],
        limits: [
          'Els protocols base xifren, no camuflen; avalua els connectors per separat si necessites cobertura.',
          'Un connector SIP003 només per a TCP no s’ha de prendre per camuflatge d’UDP.',
        ],
      },
      {
        title: 'Hysteria 2',
        description:
          'Una solució centrada en QUIC amb un disseny propi de control de congestió; considera-la si UDP és accessible de manera fiable.',
        strengths: [
          'Via UDP amb datagrames no fiables, dissenyada per a xarxes amb moltes pèrdues i un control de congestió afinat per a condicions dures.',
        ],
        limits: [
          'Si UDP està bloquejat o restringit perd l’avantatge principal, i el disseny no garanteix més velocitat a la teva xarxa.',
          'El TCP encara viatja com a fluxos QUIC, així que les pèrdues poden bloquejar els fluxos com en qualsevol transport fiable.',
        ],
      },
    ],
    caveat:
      'Límits de l’empremta: chrome-latest segueix el perfil històric de Chrome 150. Les captures de Chrome 153 no demostren una equivalència completa d’empremta. ML-DSA vincula la clau pública del certificat temporal; ML-KEM només intervé en la derivació de claus si es negocia un grup híbrid. La sonda de destinació del CLI estàndard fa servir ring sense suport per a ML-KEM, de manera que no hi ha cap garantia postquàntica d’extrem a extrem per defecte.',
  },
  security: {
    eyebrow: 'Seguretat i responsabilitat',
    title: 'La confiança comença\namb claredat.',
    description:
      'Allotjar el transport et dona el control de tots dos extrems. També exigeix protegir les credencials, restringir l’accés i entendre què no pot amagar la cobertura.',
    principles: [
      {
        title: 'Protegeix les claus i les credencials',
        description:
          'No incloguis claus privades del servidor ni credencials del client en configuracions compartides, registres o informes públics. Restringeix l’accés als fitxers que les contenen.',
      },
      {
        title: 'Limita l’accés local al teu dispositiu',
        description:
          'El servei SOCKS5 local no té autenticació. Vincula’l a la interfície de bucle local; exposar-lo a altres dispositius requereix controls d’accés addicionals.',
      },
      {
        title: 'Mantén HTTPS d’extrem a extrem',
        description:
          'Fes servir HTTPS a les aplicacions encara que el trànsit passi per Umbra. Vision només retira el xifratge extern redundant quan es compleixen les condicions; no substitueix el TLS de l’aplicació.',
      },
      {
        title: 'Coneix els límits de la cobertura',
        description:
          'Les peticions no autenticades van a la destinació real, sense un rebuig propi d’un intermediari. Això no fa indistingible tot el trànsit ni impedeix que un observador el pugui detectar.',
      },
    ],
    limitsTitle: 'Entén els límits',
    limits: [
      'Umbra és programari alfa; aquesta pàgina no acredita cap auditoria de seguretat independent.',
      'Mantén HTTPS a les aplicacions. Un transport privat no fa fiables els dispositius, navegadors ni serveis de destinació.',
      'El servei SOCKS5 local no té autenticació. Fes servir la interfície de bucle local si no controles l’accés d’una altra manera.',
      'No s’ha demostrat equivalència completa amb Chrome. La detectabilitat depèn de la xarxa i de les capacitats de l’observador.',
      'Protegeix les claus privades del servidor i les credencials del client. El desplegament, les actualitzacions i els dispositius continuen sent responsabilitat teva.',
    ],
    disclosure: 'Comunica problemes sense exposar secrets.',
    disclosureDescription:
      'El codi i el model de seguretat són públics. Consulta les indicacions actuals del repositori abans de comunicar una vulnerabilitat; no publiquis credencials ni detalls sensibles.',
    source: 'Obre el repositori',
  },
  changelog: {
    eyebrow: 'Novetats de cada versió',
    title: 'Què canvia per a tu.',
    description:
      'Canvis en la gestió de connexions i detalls que cal revisar quan actualitzes el desplegament.',
    prerelease: 'Versió preliminar',
    heading: 'Novetats per a connexions compartides i UDP',
    summary:
      'Aquesta alfa actualitza la gestió de les connexions compartides i del trànsit UDP. Continua disponible TCP/Vision + QUIC UDP en una sola instància; aquests canvis no prometen més velocitat a totes les xarxes.',
    changes: [
      'El maquinari compatible pot accelerar la criptografia; reutilitzar contextos de xifratge TLS evita repetir-ne la inicialització.',
      'En compartir connexions TCP amb mux, es planifiquen els fluxos preparats amb finestres inicials més grans dins dels pressupostos de memòria.',
      'QUIC rep trànsit per lots i fa avançar UDP de manera independent; BBR continua sent el control de congestió predeterminat.',
      'Els diagnòstics numèrics opcionals permeten examinar el transport sense informar de destinacions ni credencials.',
    ],
    upgrade:
      'Actualitza tots dos extrems per al mux adaptatiu. Revisa la configuració de rendiment i la verificació de la versió abans del desplegament.',
    read: 'Llegeix les notes de versió',
  },
};

/** Typed page content and react-i18next share one complete seven-language source. */
export const marketingCopy: Record<Locale, MarketingCopy> = {
  'zh-hans': zhHans,
  'zh-hant': zhHant,
  en,
  fr,
  es,
  ja,
  ca,
};

export const marketingResources = Object.fromEntries(
  Object.entries(marketingCopy).map(([locale, copy]) => [
    locale,
    { marketing: copy },
  ]),
) as Record<Locale, { marketing: MarketingCopy }>;
