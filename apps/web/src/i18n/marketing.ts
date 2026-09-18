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
    copyCode: string;
    copyLink: string;
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
    read: string;
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
    read: string;
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
    read: string;
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
    externalRead: string;
    upgradeRead: string;
    sourceRead: string;
    performanceRead: string;
    back: string;
  };
}

export const marketingCopy: Record<Locale, MarketingCopy> = {
  "en": {
    "nav": {
      "docs": "Documentation",
      "protocol": "How it works",
      "download": "Download",
      "security": "Security",
      "changelog": "Changelog",
      "github": "GitHub"
    },
    "ui": {
      "language": "Language",
      "theme": "Toggle color theme",
      "menu": "Open navigation",
      "skip": "Skip to content",
      "copy": "Copy commands",
      "copied": "Copied",
      "copyFailed": "Couldn't copy. Select the commands and copy them manually.",
      "close": "Close",
      "copyCode": "Copy code",
      "copyLink": "Copy link"
    },
    "pages": {
      "download": {
        "title": "Get Umbra",
        "description": "One binary, client and server modes. Choose a published build for your platform and architecture, or build from source."
      },
      "protocol": {
        "title": "Understand the connection. Choose your setup.",
        "description": "Umbra combines website cover, authentication and a choice of transports. Match the connection to your network and apps while keeping one local proxy."
      },
      "security": {
        "title": "Own your connection. Protect your setup.",
        "description": "A few practical settings help you protect keys, control access and keep your deployment working."
      },
      "changelog": {
        "title": "See what's changed. Plan your next upgrade.",
        "description": "Find improvements in each release and the steps needed to update your client and server."
      },
      "home": {
        "title": "Your connection. Your control.",
        "description": "Umbra is an open-source proxy you host yourself. Connect through your own server, use a real website as cover, and bring your everyday apps together behind one local proxy."
      }
    },
    "hero": {
      "badge": "1.0.0-alpha is available",
      "title": "Your connection.",
      "accent": "Your control.",
      "description": "Umbra is an open-source proxy you host yourself. Connect through your own server, use a real website as cover, and bring your everyday apps together behind one local proxy.",
      "start": "Quick start",
      "explore": "How it works",
      "footnote": "MIT licensed · Self-hosted · Alpha"
    },
    "diagram": {
      "client": "Your device",
      "transport": "Proxy connection",
      "internet": "Internet",
      "cover": "Cover website",
      "authenticated": "Verified client",
      "fallback": "Other connections → website",
      "caption": "Verified clients use the proxy; other connections receive the real website's response."
    },
    "facts": [
      "Real website cover",
      "Choose your transport",
      "Connect your apps",
      "Open-source, self-hosted"
    ],
    "principles": {
      "eyebrow": "Why Umbra",
      "title": "Run your connection.\nKeep your tools.",
      "description": "Website cover, flexible transports and a local proxy, brought together to make a self-hosted setup easier to use.",
      "features": [
        {
          "title": "A real website at the same entrance",
          "description": "Your client authenticates to use the proxy. Other connections go to the website you configure and receive its normal response."
        },
        {
          "title": "Built around Chrome's connection patterns",
          "description": "Umbra uses Chrome handshake profiles to shape how a connection begins, bringing familiar browser behavior to proxy transport."
        },
        {
          "title": "No node certificate renewals",
          "description": "Keys verify the connection's identity, so you can skip applying for and renewing a public CA certificate for your Umbra node."
        },
        {
          "title": "One local proxy for your apps",
          "description": "Connect SOCKS5-capable apps directly. Keep your Clash-compatible client's interface and routing rules while Umbra handles the remote connection."
        }
      ]
    },
    "start": {
      "eyebrow": "Make your first connection",
      "title": "Set up both ends.\nConnect an app.",
      "description": "Download a build for your device, generate keys and configure the server and client. The quick start walks you through connecting an app to local SOCKS5.",
      "link": "Follow the quick start",
      "terminal": "Build from source"
    },
    "docs": {
      "eyebrow": "Documentation",
      "title": "From first connection to your own setup.",
      "description": "Find the guide for what you want to do next.",
      "cards": [
        {
          "title": "Meet Umbra",
          "description": "Learn what it does and what you'll need to get started."
        },
        {
          "title": "Configure your connection",
          "description": "Look up server and client settings and choose a transport."
        },
        {
          "title": "Compare proxy setups",
          "description": "Choose based on your network, maintenance needs and apps."
        }
      ]
    },
    "cta": {
      "title": "Make the connection yours.",
      "description": "Start with one server and one app. Follow the guide to your first working connection."
    },
    "footer": {
      "description": "An open-source proxy you host yourself.",
      "project": "Project",
      "resources": "Resources",
      "legal": "For privacy and open internet access. Follow applicable laws.",
      "license": "Released under the MIT license."
    },
    "download": {
      "eyebrow": "Download and install",
      "title": "Get Umbra",
      "description": "One binary, client and server modes. Choose a published build for your platform and architecture, or build from source.",
      "alpha": "Alpha prerelease. Follow the quick start to configure both ends.",
      "platform": "Platform",
      "architecture": "Architecture",
      "releases": "View downloads",
      "source": "Build from source",
      "sourceDescription": "Want to build it yourself or explore the implementation? Clone the repository and compile both modes. Use the same version at both ends.",
      "verify": "Before you download",
      "verifyDescription": "Choose a version on the official releases page and check the supplied verification information. Available platforms and architectures are listed with that release.",
      "requirements": "Use the repository's pinned Rust toolchain, currently 1.96.1.",
      "read": "View installation steps"
    },
    "protocol": {
      "eyebrow": "How it works",
      "title": "Understand the connection.\nChoose your setup.",
      "description": "Umbra combines website cover, authentication and a choice of transports. Match the connection to your network and apps while keeping one local proxy.",
      "steps": [
        {
          "title": "Cover the entrance with a real website",
          "description": "Verified clients enter the proxy; other connections go to the configured website. Key-based identity avoids public CA certificate renewals for the node."
        },
        {
          "title": "Reduce repeated connection work",
          "description": "TCP multiplexing lets requests share connections. Dedicated Vision can forward eligible, already-encrypted HTTPS data with less outer encryption."
        },
        {
          "title": "Give TCP and UDP their own paths",
          "description": "Choose different transports for TCP and UDP behind one SOCKS5 proxy. QUIC needs a working UDP path and a QUIC-capable cover website."
        }
      ],
      "implementation": "Choose for the way you work",
      "implementationDescription": "Compare what you'll maintain, how requests travel and how your apps connect. Xray here refers to VLESS + REALITY + Vision over TCP.",
      "strengthsLabel": "Useful for",
      "limitsLabel": "Before you start",
      "layers": [
        {
          "title": "Umbra",
          "description": "A client/server pair combining website cover with TCP and QUIC.",
          "strengths": [
            "Managing both ends and connecting apps through one entry point."
          ],
          "limits": [
            "Currently an Alpha CLI; use compatible versions at both ends."
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "REALITY and Vision within the Xray platform.",
          "strengths": [
            "Configuring protocols, transports and routing in Xray."
          ],
          "limits": [
            "Match core settings, flow and client support."
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "An encrypted proxy protocol with a choice of underlying transports.",
          "strengths": [
            "Working with applications that already support VMess."
          ],
          "limits": [
            "Check client versions and the chosen transport combination."
          ]
        },
        {
          "title": "Trojan",
          "description": "TLS-based proxying with website fallback.",
          "strengths": [
            "A conventional TLS service deployment."
          ],
          "limits": [
            "Typical setups maintain a domain and certificate; UDP travels over TCP."
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "Key-based encrypted proxying.",
          "strengths": [
            "Configuring TCP and UDP proxying with a key."
          ],
          "limits": [
            "Website cover or extra transport plugins require separate setup."
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "QUIC-based transport with unreliable datagrams for UDP.",
          "strengths": [
            "Using QUIC and evaluating real-time UDP applications."
          ],
          "limits": [
            "Requires a usable UDP path and TLS configuration."
          ]
        }
      ],
      "caveat": "Transports follow your configuration. Read the guides for setup steps and the requirements of each mode.",
      "read": "Read the full comparison"
    },
    "security": {
      "eyebrow": "Use Umbra securely",
      "title": "Own your connection.\nProtect your setup.",
      "description": "A few practical settings help you protect keys, control access and keep your deployment working.",
      "principles": [
        {
          "title": "Keep keys private",
          "description": "Store server private keys only on the server. Share client configuration through a trusted channel and limit access to configuration files."
        },
        {
          "title": "Keep the local proxy local",
          "description": "Listen on 127.0.0.1:1080 as shown in the examples. Set access controls before allowing other devices to connect."
        },
        {
          "title": "Continue using HTTPS",
          "description": "Keep encryption between your app and its destination. Vision forwards already-encrypted data when eligible, reducing repeated outer processing."
        },
        {
          "title": "Keep both ends in step",
          "description": "Read release notes, save a working binary and configuration, and update both ends when the protocol changes."
        }
      ],
      "limitsTitle": "Understand the protection",
      "limits": [
        "Release stage: Umbra is Alpha software, with no published evidence of a completed independent security audit.",
        "Network visibility: ordinary connections receive a real website response; addresses, timing and traffic patterns can still be observed.",
        "Devices and services: protect devices, browser accounts and destinations separately, and keep application HTTPS enabled.",
        "Browser profiles: the current handshake profile is based on Chrome 150. The security model explains its scope."
      ],
      "disclosure": "Report a security issue",
      "disclosureDescription": "Check the repository's security page for reporting options before contacting maintainers. Remove credentials and sensitive deployment details from public discussions.",
      "source": "View security reporting guidance",
      "read": "Read the security model"
    },
    "changelog": {
      "eyebrow": "Release updates",
      "title": "See what's changed.\nPlan your next upgrade.",
      "description": "Find improvements in each release and the steps needed to update your client and server.",
      "prerelease": "Prerelease",
      "heading": "Better handling of shared connections and UDP",
      "summary": "This release improves encryption processing, shared-connection scheduling and QUIC reception, while keeping single-instance TCP/Vision and QUIC UDP available.",
      "changes": [
        "Less repeated initialization: reusable TLS cipher contexts and cryptographic acceleration on supported hardware.",
        "Work where data is ready: schedule ready streams and enlarge startup windows within memory budgets.",
        "Improved UDP handling: batched QUIC reception and independently progressing UDP reads and writes; BBR remains the default.",
        "Easier troubleshooting: optional numeric diagnostics show transport state without destination addresses or credentials."
      ],
      "upgrade": "Update both ends for adaptive connection multiplexing. Keep your working binaries and configuration, then verify the upgrade using the guide.",
      "read": "View this update",
      "externalRead": "Open GitHub release",
      "upgradeRead": "Read the upgrade guide",
      "sourceRead": "Project overview",
      "performanceRead": "Performance and configuration",
      "back": "All updates"
    }
  },
  "zh-hans": {
    "nav": {
      "docs": "文档",
      "protocol": "工作原理",
      "download": "下载",
      "security": "安全",
      "changelog": "更新日志",
      "github": "GitHub"
    },
    "ui": {
      "language": "语言",
      "theme": "切换明暗主题",
      "menu": "打开导航",
      "skip": "跳到正文",
      "copy": "复制命令",
      "copied": "已复制",
      "copyFailed": "复制失败，请选中命令后手动复制。",
      "close": "关闭",
      "copyCode": "复制代码",
      "copyLink": "复制链接"
    },
    "pages": {
      "download": {
        "title": "获取 Umbra",
        "description": "一个程序，包含客户端和服务端。按设备的平台和架构选择发布文件，也可以从源码构建。"
      },
      "protocol": {
        "title": "了解连接如何工作， 选好自己的配置。",
        "description": "Umbra 将网站掩护、连接认证和多种传输方式组合在一起。你可以根据网络和应用需求，选择连接方式，并沿用一个本地代理入口。"
      },
      "security": {
        "title": "让连接由你管理， 让保护落实到配置。",
        "description": "从保管密钥到限制访问，几个明确的设置能帮助你安全地运行 Umbra。"
      },
      "changelog": {
        "title": "了解新变化， 安排下一次升级。",
        "description": "查看每个版本的改进，以及升级客户端与服务端时需要做的准备。"
      },
      "home": {
        "title": "你的连接， 由你掌控。",
        "description": "Umbra 是开源的自建代理工具。用自己的服务器连接互联网，以真实网站作为掩护，并通过一个本地代理入口接入常用应用。"
      }
    },
    "hero": {
      "badge": "1.0.0-alpha 现已发布",
      "title": "你的连接，",
      "accent": "由你掌控。",
      "description": "Umbra 是开源的自建代理工具。用自己的服务器连接互联网，以真实网站作为掩护，并通过一个本地代理入口接入常用应用。",
      "start": "快速开始",
      "explore": "了解工作原理",
      "footnote": "MIT 开源 · 自主部署 · Alpha 版本"
    },
    "diagram": {
      "client": "你的设备",
      "transport": "代理连接",
      "internet": "互联网",
      "cover": "掩护网站",
      "authenticated": "已验证的客户端",
      "fallback": "其他访问 → 掩护网站",
      "caption": "客户端通过验证后连接代理；其他访问由真实网站响应。"
    },
    "facts": [
      "真实网站掩护",
      "按需选择传输",
      "接入常用应用",
      "开源，自主部署"
    ],
    "principles": {
      "eyebrow": "为什么选择 Umbra",
      "title": "自己管理连接，\n继续使用熟悉的工具。",
      "description": "把网站掩护、灵活的传输方式和本地代理入口放在一起，让自建代理更方便配置和使用。",
      "features": [
        {
          "title": "用真实网站掩护代理入口",
          "description": "你的客户端通过验证后建立代理连接。其他访问则转发到你配置的真实网站，看到网站的正常响应，让同一个入口也能应对普通网站访问。"
        },
        {
          "title": "参考 Chrome 的连接方式",
          "description": "以 Chrome 的连接特征为参考，设计连接建立时发送的信息，让代理传输更贴近日常浏览网站的方式。"
        },
        {
          "title": "省去节点证书的申请和续期",
          "description": "Umbra 通过密钥验证连接身份，无需为代理节点申请和定期续签公网 CA 证书，日常维护少一项工作。"
        },
        {
          "title": "一个入口，接入现有应用",
          "description": "支持 SOCKS5 的应用可直接接入。使用 Clash 类客户端时，也能保留熟悉的界面和分流规则，把远端连接交给 Umbra。"
        }
      ]
    },
    "start": {
      "eyebrow": "开始使用",
      "title": "装好两端，\n连接你的第一个应用。",
      "description": "下载适合设备的版本，生成密钥并完成两端配置，再把应用接到本地 SOCKS5 代理。快速开始会带你完成第一次连接。",
      "link": "跟着指南开始",
      "terminal": "从源码构建"
    },
    "docs": {
      "eyebrow": "文档入口",
      "title": "从第一次连接，到按需配置。",
      "description": "按你当前要做的事，找到对应指南。",
      "cards": [
        {
          "title": "认识 Umbra",
          "description": "了解它能做什么，以及开始前需要准备什么。"
        },
        {
          "title": "配置你的连接",
          "description": "查阅服务端与客户端字段，选择需要的传输方式。"
        },
        {
          "title": "比较代理方案",
          "description": "从网络、维护和应用接入方式，找到适合自己的方案。"
        }
      ]
    },
    "cta": {
      "title": "开始建立自己的连接。",
      "description": "从一台服务器和一个应用开始，按指南完成首次连接。"
    },
    "footer": {
      "description": "开源的自建代理工具。",
      "project": "项目",
      "resources": "资源",
      "legal": "用于隐私保护与开放互联网访问，请遵守适用法律。",
      "license": "源码采用 MIT 许可证。"
    },
    "download": {
      "eyebrow": "下载与安装",
      "title": "获取 Umbra",
      "description": "一个程序，包含客户端和服务端。按设备的平台和架构选择发布文件，也可以从源码构建。",
      "alpha": "Alpha 预发布版本。首次使用请按快速开始配置两端。",
      "platform": "平台",
      "architecture": "架构",
      "releases": "查看下载文件",
      "source": "从源码构建",
      "sourceDescription": "想自行构建或查看实现？克隆仓库后即可编译客户端与服务端。两端请使用同一版本。",
      "verify": "下载前确认",
      "verifyDescription": "从官方发布页面选择对应版本，并按页面提供的信息核对下载文件。可下载的平台与架构以该版本附件为准。",
      "requirements": "使用仓库指定的 Rust 工具链，当前为 1.96.1。",
      "read": "查看安装步骤"
    },
    "protocol": {
      "eyebrow": "工作原理",
      "title": "了解连接如何工作，\n选好自己的配置。",
      "description": "Umbra 将网站掩护、连接认证和多种传输方式组合在一起。你可以根据网络和应用需求，选择连接方式，并沿用一个本地代理入口。",
      "steps": [
        {
          "title": "用真实网站掩护入口",
          "description": "通过验证的客户端建立代理连接，其他连接转发到配置的真实网站。节点通过密钥验证身份，省去申请和续期公网 CA 证书的工作。"
        },
        {
          "title": "减少重复建连与加密",
          "description": "TCP 连接复用让多个请求共享连接，减少反复建连。选择独立 Vision 模式后，符合条件的 HTTPS 流量可直接转发已加密数据，减少外层重复加密。"
        },
        {
          "title": "分别安排 TCP 与 UDP",
          "description": "你可以让 TCP 和 UDP 请求使用不同的传输方式，同时保留一个本地 SOCKS5 入口。选择 QUIC 时，需要可用的 UDP 网络和支持 QUIC 的掩护网站。"
        }
      ],
      "implementation": "按使用需求比较方案",
      "implementationDescription": "从需要维护的内容、传输路径和现有客户端支持来选择。下表中的 Xray 指 VLESS + REALITY + Vision 的 TCP 组合。",
      "strengthsLabel": "适合的需求",
      "limitsLabel": "使用前确认",
      "layers": [
        {
          "title": "Umbra",
          "description": "一套客户端与服务端，整合网站掩护和 TCP/QUIC。",
          "strengths": [
            "希望自己管理两端，并用一个入口接入应用。"
          ],
          "limits": [
            "当前为 Alpha 命令行程序；两端使用匹配版本。"
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "在 Xray 中组合 REALITY 与 Vision。",
          "strengths": [
            "希望在 Xray 中配置相应协议、传输和路由。"
          ],
          "limits": [
            "核心配置、flow 和客户端支持需匹配。"
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "加密代理协议，可搭配不同传输。",
          "strengths": [
            "现有应用已经支持 VMess。"
          ],
          "limits": [
            "确认客户端版本及具体传输组合。"
          ]
        },
        {
          "title": "Trojan",
          "description": "基于 TLS，支持未认证请求回落到网站。",
          "strengths": [
            "希望采用常规 TLS 服务的部署方式。"
          ],
          "limits": [
            "常见部署需要维护域名和证书；UDP 经 TCP 承载。"
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "基于密钥的加密代理。",
          "strengths": [
            "希望用密钥配置 TCP/UDP 代理。"
          ],
          "limits": [
            "额外的网站掩护或传输插件需要单独配置。"
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "基于 QUIC，UDP 使用不可靠数据报。",
          "strengths": [
            "希望使用 QUIC，并评估实时 UDP 应用。"
          ],
          "limits": [
            "网络需支持 UDP，并配置 TLS。"
          ]
        }
      ],
      "caveat": "传输方式由配置决定。查看详细指南，了解各模式的设置方法和使用条件。",
      "read": "查看详细对比"
    },
    "security": {
      "eyebrow": "安全使用",
      "title": "让连接由你管理，\n让保护落实到配置。",
      "description": "从保管密钥到限制访问，几个明确的设置能帮助你安全地运行 Umbra。",
      "principles": [
        {
          "title": "妥善保管密钥",
          "description": "服务端私钥只保存在服务器上，客户端配置通过可信渠道传递。限制配置文件的读取权限，分享日志前移除凭证。"
        },
        {
          "title": "本地代理只向本机开放",
          "description": "按示例监听 127.0.0.1:1080，让本地代理仅供本机应用使用。需要提供给其他设备时，先设置访问控制。"
        },
        {
          "title": "继续使用 HTTPS",
          "description": "让应用与目标网站之间保持加密连接。Vision 会在适用时转发应用已经加密的数据，减少外层重复处理。"
        },
        {
          "title": "保持两端版本一致",
          "description": "升级前阅读版本说明，保留可回退的程序和配置。涉及协议变化时，同时更新客户端与服务端。"
        }
      ],
      "limitsTitle": "了解保护范围",
      "limits": [
        "软件阶段：当前为 Alpha 版本，尚无独立安全审计完成的公开依据。",
        "网络观察：网站掩护会让普通访问获得真实网站响应；连接地址、时间和流量特征仍可能被观察。",
        "设备与服务：设备、浏览器账户和目标网站的安全需要分别管理。应用继续使用 HTTPS。",
        "浏览器特征：当前使用 Chrome 150 握手档案，覆盖范围见安全模型中的版本说明。"
      ],
      "disclosure": "报告安全问题",
      "disclosureDescription": "先查看仓库安全页面中的报告方式，再联系维护者。公开讨论时请移除真实凭证和敏感部署信息。",
      "source": "查看安全报告指引",
      "read": "阅读安全模型"
    },
    "changelog": {
      "eyebrow": "版本更新",
      "title": "了解新变化，\n安排下一次升级。",
      "description": "查看每个版本的改进，以及升级客户端与服务端时需要做的准备。",
      "prerelease": "预发布版本",
      "heading": "改进多连接与 UDP 处理",
      "summary": "本次更新优化加密处理、共享连接调度和 QUIC 数据接收，继续支持一个实例同时使用 TCP/Vision 与 QUIC UDP。",
      "changes": [
        "减少重复初始化：复用 TLS 加密上下文，并在支持的硬件上使用密码学加速。",
        "按需推进共享连接：优先处理已有数据可读写的流，在内存预算内扩大启动窗口。",
        "改进 UDP 处理：QUIC 批量接收数据，UDP 读写分别推进；默认继续使用 BBR 拥塞控制。",
        "更方便定位问题：可按需开启数值诊断，查看传输状态，输出中省略目标地址和凭证。"
      ],
      "upgrade": "使用自适应连接复用时，请同时升级客户端与服务端。先保留原有程序和配置，再按升级指南验证连接。",
      "read": "查看本次更新",
      "externalRead": "前往 GitHub 发布页",
      "upgradeRead": "阅读升级指南",
      "sourceRead": "项目说明",
      "performanceRead": "性能与配置说明",
      "back": "全部更新"
    }
  },
  "zh-hant": {
    "nav": {
      "docs": "文件",
      "protocol": "工作原理",
      "download": "下載",
      "security": "安全",
      "changelog": "更新紀錄",
      "github": "GitHub"
    },
    "ui": {
      "language": "語言",
      "theme": "切換明暗主題",
      "menu": "打開導航",
      "skip": "跳到正文",
      "copy": "複製指令",
      "copied": "已複製",
      "copyFailed": "複製失敗，請選中指令後手動複製。",
      "close": "關閉",
      "copyCode": "複製程式碼",
      "copyLink": "複製連結"
    },
    "pages": {
      "download": {
        "title": "獲取 Umbra",
        "description": "一個程式，包含用戶端和伺服器端。按裝置的平台和架構選擇發佈檔案，也可以從原始碼建置。"
      },
      "protocol": {
        "title": "瞭解連線如何工作， 選好自己的設定。",
        "description": "Umbra 將網站掩護、連線認證和多種傳輸方式組合在一起。你可以根據網路和應用程式需求，選擇連線方式，並沿用一個本機代理入口。"
      },
      "security": {
        "title": "讓連線由你管理， 讓保護落實到設定。",
        "description": "從保管金鑰到限制存取，幾個明確的設定能幫助你安全地執行 Umbra。"
      },
      "changelog": {
        "title": "瞭解新變化， 安排下一次升級。",
        "description": "查看每個版本的改進，以及升級用戶端與伺服器端時需要做的準備。"
      },
      "home": {
        "title": "你的連線， 由你掌控。",
        "description": "Umbra 是開放原始碼的自建代理工具。用自己的伺服器連線互聯網，以實際網站作為掩護，並通過一個本機代理入口連接常用應用程式。"
      }
    },
    "hero": {
      "badge": "1.0.0-alpha 現已發佈",
      "title": "你的連線，",
      "accent": "由你掌控。",
      "description": "Umbra 是開放原始碼的自建代理工具。用自己的伺服器連線互聯網，以實際網站作為掩護，並通過一個本機代理入口連接常用應用程式。",
      "start": "快速開始",
      "explore": "瞭解工作原理",
      "footnote": "MIT 開放原始碼 · 自主部署 · Alpha 版本"
    },
    "diagram": {
      "client": "你的裝置",
      "transport": "代理連線",
      "internet": "互聯網",
      "cover": "掩護網站",
      "authenticated": "已驗證的用戶端",
      "fallback": "其他存取 → 掩護網站",
      "caption": "用戶端通過驗證後連線代理；其他存取由實際網站回應。"
    },
    "facts": [
      "實際網站掩護",
      "依需求選擇傳輸",
      "連接常用應用程式",
      "開放原始碼，自主部署"
    ],
    "principles": {
      "eyebrow": "為什麼選擇 Umbra",
      "title": "自己管理連線，\n繼續使用熟悉的工具。",
      "description": "把網站掩護、靈活的傳輸方式和本機代理入口放在一起，讓自建代理更方便設定和使用。",
      "features": [
        {
          "title": "用實際網站掩護代理入口",
          "description": "你的用戶端通過驗證後建立代理連線。其他存取則轉發到你設定的實際網站，看到網站的正常回應，讓同一個入口也能應對一般網站瀏覽。"
        },
        {
          "title": "參考 Chrome 的連線方式",
          "description": "以 Chrome 的連線特徵為參考，設計連線建立時發送的資訊，讓代理傳輸更貼近日常瀏覽網站的方式。"
        },
        {
          "title": "省去節點憑證的申請和續期",
          "description": "Umbra 通過金鑰驗證連線身分，不必為代理節點申請和定期續簽公開網路 CA 憑證，日常維護少一項工作。"
        },
        {
          "title": "一個入口，連接現有應用程式",
          "description": "支援 SOCKS5 的應用程式可直接連接。使用 Clash 類用戶端時，也能保留熟悉的介面和分流規則，把遠端連線交給 Umbra。"
        }
      ]
    },
    "start": {
      "eyebrow": "開始使用",
      "title": "裝好兩端，\n連線你的第一個應用程式。",
      "description": "下載適合裝置的版本，產生金鑰並完成兩端設定，再把應用程式接到本機 SOCKS5 代理。快速開始會帶你完成第一次連線。",
      "link": "跟著指南開始",
      "terminal": "從原始碼建置"
    },
    "docs": {
      "eyebrow": "文件入口",
      "title": "從第一次連線，到依需求設定。",
      "description": "按你目前要做的事，找到對應指南。",
      "cards": [
        {
          "title": "認識 Umbra",
          "description": "瞭解它能做什麼，以及開始前需要準備什麼。"
        },
        {
          "title": "設定你的連線",
          "description": "查閱伺服器端與用戶端欄位，選擇需要的傳輸方式。"
        },
        {
          "title": "比較代理方案",
          "description": "從網路、維護和應用程式連接方式，找到適合自己的方案。"
        }
      ]
    },
    "cta": {
      "title": "開始建立自己的連線。",
      "description": "從一部伺服器和一個應用程式開始，按指南完成第一次連線。"
    },
    "footer": {
      "description": "開放原始碼的自建代理工具。",
      "project": "項目",
      "resources": "資源",
      "legal": "用於隱私保護與開放互聯網存取，請遵守適用法律。",
      "license": "原始碼採用 MIT 授權條款。"
    },
    "download": {
      "eyebrow": "下載與安裝",
      "title": "獲取 Umbra",
      "description": "一個程式，包含用戶端和伺服器端。按裝置的平台和架構選擇發佈檔案，也可以從原始碼建置。",
      "alpha": "Alpha 預發佈版本。第一次使用請按快速開始設定兩端。",
      "platform": "平台",
      "architecture": "架構",
      "releases": "查看下載檔案",
      "source": "從原始碼建置",
      "sourceDescription": "想自行建置或查看實現？克隆儲存庫後即可編譯用戶端與伺服器端。兩端請使用同一版本。",
      "verify": "下載前確認",
      "verifyDescription": "從官方發佈頁面選擇對應版本，並按頁面提供的資訊核對下載檔案。可下載的平台與架構以該版本附件為準。",
      "requirements": "使用儲存庫指定的 Rust 工具鏈，目前為 1.96.1。",
      "read": "查看安裝步驟"
    },
    "protocol": {
      "eyebrow": "工作原理",
      "title": "瞭解連線如何工作，\n選好自己的設定。",
      "description": "Umbra 將網站掩護、連線認證和多種傳輸方式組合在一起。你可以根據網路和應用程式需求，選擇連線方式，並沿用一個本機代理入口。",
      "steps": [
        {
          "title": "用實際網站掩護入口",
          "description": "通過驗證的用戶端建立代理連線，其他連線轉發到設定的實際網站。節點通過金鑰驗證身分，省去申請和續期公開網路 CA 憑證的工作。"
        },
        {
          "title": "減少重複建連與加密",
          "description": "TCP 連線重複使用讓多個請求共享連線，減少反覆建連。選擇獨立 Vision 模式後，符合條件的 HTTPS 流量可直接轉發已加密資料，減少外層重複加密。"
        },
        {
          "title": "分別安排 TCP 與 UDP",
          "description": "你可以讓 TCP 和 UDP 請求使用不同的傳輸方式，同時保留一個本機 SOCKS5 入口。選擇 QUIC 時，需要可用的 UDP 網路和支援 QUIC 的掩護網站。"
        }
      ],
      "implementation": "按使用需求比較方案",
      "implementationDescription": "從需要維護的內容、傳輸路徑和現有用戶端支援來選擇。下表中的 Xray 指 VLESS + REALITY + Vision 的 TCP 組合。",
      "strengthsLabel": "適合的需求",
      "limitsLabel": "使用前確認",
      "layers": [
        {
          "title": "Umbra",
          "description": "一套用戶端與伺服器端，整合網站掩護和 TCP/QUIC。",
          "strengths": [
            "希望自己管理兩端，並用一個入口連接應用程式。"
          ],
          "limits": [
            "目前為 Alpha 命令列程式；兩端使用匹配版本。"
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "在 Xray 中組合 REALITY 與 Vision。",
          "strengths": [
            "希望在 Xray 中設定相應協議、傳輸和路由。"
          ],
          "limits": [
            "核心設定、flow 和用戶端支援需匹配。"
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "加密代理協議，可搭配不同傳輸。",
          "strengths": [
            "現有應用程式已經支援 VMess。"
          ],
          "limits": [
            "確認用戶端版本及具體傳輸組合。"
          ]
        },
        {
          "title": "Trojan",
          "description": "基於 TLS，支援未認證請求轉送到網站。",
          "strengths": [
            "希望採用常規 TLS 服務的部署方式。"
          ],
          "limits": [
            "常見部署需要維護網域名稱和憑證；UDP 經 TCP 承載。"
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "基於金鑰的加密代理。",
          "strengths": [
            "希望用金鑰設定 TCP/UDP 代理。"
          ],
          "limits": [
            "額外的網站掩護或傳輸插件需要單獨設定。"
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "基於 QUIC，UDP 使用不可靠資料報。",
          "strengths": [
            "希望使用 QUIC，並評估即時 UDP 應用程式。"
          ],
          "limits": [
            "網路需支援 UDP，並設定 TLS。"
          ]
        }
      ],
      "caveat": "傳輸方式由設定決定。查看詳細指南，瞭解各模式的設定方法和使用條件。",
      "read": "查看詳細對比"
    },
    "security": {
      "eyebrow": "安全使用",
      "title": "讓連線由你管理，\n讓保護落實到設定。",
      "description": "從保管金鑰到限制存取，幾個明確的設定能幫助你安全地執行 Umbra。",
      "principles": [
        {
          "title": "妥善保管金鑰",
          "description": "伺服器端私密金鑰只保存在伺服器上，用戶端設定透過可信管道傳遞。限制設定檔案的讀取權限，分享紀錄前移除認證資訊。"
        },
        {
          "title": "本機代理只向本機開放",
          "description": "依照範例接聽 127.0.0.1:1080，讓本機代理僅供本機應用程式使用。需要提供給其他裝置時，先設定存取控制。"
        },
        {
          "title": "繼續使用 HTTPS",
          "description": "讓應用程式與目標網站之間保持加密連線。Vision 會在適用時轉發應用程式已經加密的資料，減少外層重複處理。"
        },
        {
          "title": "保持兩端版本一致",
          "description": "升級前閱讀版本說明，保留可還原的程式和設定。涉及協議變化時，同時更新用戶端與伺服器端。"
        }
      ],
      "limitsTitle": "瞭解保護範圍",
      "limits": [
        "軟體階段：目前為 Alpha 版本，尚無獨立安全稽核完成的公開依據。",
        "網路觀察：網站掩護會讓一般瀏覽獲得實際網站回應；連線位址、時間和流量特徵仍可能被觀察。",
        "裝置與服務：裝置、瀏覽器帳戶和目標網站的安全需要分別管理。應用程式繼續使用 HTTPS。",
        "瀏覽器特徵：目前使用 Chrome 150 握手設定檔，涵蓋範圍見安全模型中的版本說明。"
      ],
      "disclosure": "報告安全問題",
      "disclosureDescription": "先查看儲存庫安全頁面中的報告方式，再聯繫維護者。公開討論時請移除真實認證資訊和敏感部署資訊。",
      "source": "查看安全報告指引",
      "read": "閱讀安全模型"
    },
    "changelog": {
      "eyebrow": "版本更新",
      "title": "瞭解新變化，\n安排下一次升級。",
      "description": "查看每個版本的改進，以及升級用戶端與伺服器端時需要做的準備。",
      "prerelease": "預發佈版本",
      "heading": "改進多連線與 UDP 處理",
      "summary": "本次更新優化加密處理、共享連線排程和 QUIC 資料接收，繼續支援一個執行個體同時使用 TCP/Vision 與 QUIC UDP。",
      "changes": [
        "減少重複初始化：重複使用 TLS 加密上下文，並在支援的硬件上使用密碼學加速。",
        "依需求推進共享連線：優先處理已有資料可讀寫的流，在記憶體預算內擴大啟動視窗。",
        "改進 UDP 處理：QUIC 批量接收資料，UDP 讀寫分別推進；預設繼續使用 BBR 擁塞控制。",
        "更方便定位問題：可依需求開啟數值診斷，查看傳輸狀態，輸出中省略目標位址和認證資訊。"
      ],
      "upgrade": "使用自適應連線重複使用時，請同時升級用戶端與伺服器端。先保留原有程式和設定，再按升級指南驗證連線。",
      "read": "查看本次更新",
      "externalRead": "前往 GitHub 發佈頁",
      "upgradeRead": "閱讀升級指南",
      "sourceRead": "項目說明",
      "performanceRead": "效能與設定說明",
      "back": "全部更新"
    }
  },
  "fr": {
    "nav": {
      "docs": "Documentation",
      "protocol": "Fonctionnement",
      "download": "Télécharger",
      "security": "Sécurité",
      "changelog": "Nouveautés",
      "github": "GitHub"
    },
    "ui": {
      "language": "Langue",
      "theme": "Changer de thème",
      "menu": "Ouvrir la navigation",
      "skip": "Aller au contenu",
      "copy": "Copier les commandes",
      "copied": "Copié",
      "copyFailed": "Copie impossible. Sélectionnez les commandes pour les copier manuellement.",
      "close": "Fermer",
      "copyCode": "Copier le code",
      "copyLink": "Copier le lien"
    },
    "pages": {
      "download": {
        "title": "Obtenir Umbra",
        "description": "Un programme, deux modes : client et serveur. Choisissez un fichier publié pour votre plateforme et votre architecture, ou compilez les sources."
      },
      "protocol": {
        "title": "Comprenez la connexion. Choisissez votre configuration.",
        "description": "Umbra réunit couverture web, authentification et plusieurs transports. Adaptez la connexion à votre réseau et à vos applications tout en gardant un seul proxy local."
      },
      "security": {
        "title": "Maîtrisez la connexion. Protégez votre installation.",
        "description": "Quelques réglages concrets aident à protéger les clés, limiter les accès et entretenir le déploiement."
      },
      "changelog": {
        "title": "Découvrez les changements. Préparez la mise à jour.",
        "description": "Retrouvez les améliorations et les étapes pour mettre à jour le client et le serveur."
      },
      "home": {
        "title": "Votre connexion. À votre façon.",
        "description": "Umbra est un proxy open source à héberger vous-même. Connectez-vous par votre serveur, utilisez un véritable site web comme couverture et reliez vos applications à un seul proxy local."
      }
    },
    "hero": {
      "badge": "1.0.0-alpha est disponible",
      "title": "Votre connexion.",
      "accent": "À votre façon.",
      "description": "Umbra est un proxy open source à héberger vous-même. Connectez-vous par votre serveur, utilisez un véritable site web comme couverture et reliez vos applications à un seul proxy local.",
      "start": "Démarrage rapide",
      "explore": "Découvrir le fonctionnement",
      "footnote": "Licence MIT · Auto-hébergé · Version Alpha"
    },
    "diagram": {
      "client": "Votre appareil",
      "transport": "Connexion proxy",
      "internet": "Internet",
      "cover": "Site de couverture",
      "authenticated": "Client authentifié",
      "fallback": "Autres connexions → site web",
      "caption": "Les clients authentifiés utilisent le proxy ; les autres connexions reçoivent la réponse du site réel."
    },
    "facts": [
      "Couverture par un site réel",
      "Transport au choix",
      "Vos applications habituelles",
      "Libre et auto-hébergé"
    ],
    "principles": {
      "eyebrow": "Pourquoi Umbra ?",
      "title": "Gérez votre connexion.\nGardez vos outils.",
      "description": "Couverture web, transports au choix et proxy local réunis pour faciliter votre installation et son utilisation.",
      "features": [
        {
          "title": "Un site réel à la même adresse",
          "description": "Votre client s'authentifie pour utiliser le proxy. Les autres connexions sont transmises au site configuré et reçoivent sa réponse habituelle."
        },
        {
          "title": "Une connexion inspirée de Chrome",
          "description": "Umbra s'appuie sur les profils de négociation de Chrome pour construire le début de la connexion, en reprenant des caractéristiques courantes de la navigation web."
        },
        {
          "title": "Moins de certificats à gérer",
          "description": "L'identité est vérifiée par des clés. Vous n'avez pas à demander ni à renouveler de certificat délivré par une CA publique pour le nœud Umbra."
        },
        {
          "title": "Une entrée pour vos applications",
          "description": "Connectez directement les applications SOCKS5, ou conservez l'interface et les règles de votre client de type Clash. Umbra gère la connexion distante."
        }
      ]
    },
    "start": {
      "eyebrow": "Votre première connexion",
      "title": "Installez les deux côtés.\nConnectez une application.",
      "description": "Téléchargez la version adaptée, générez les clés et configurez serveur et client. Le démarrage rapide vous accompagne jusqu'à la première requête via SOCKS5.",
      "link": "Suivre le guide",
      "terminal": "Compiler les sources"
    },
    "docs": {
      "eyebrow": "Documentation",
      "title": "De la première connexion aux réglages sur mesure.",
      "description": "Retrouvez le guide correspondant à votre prochaine étape.",
      "cards": [
        {
          "title": "Découvrir Umbra",
          "description": "Comprenez son rôle et préparez votre installation."
        },
        {
          "title": "Configurer la connexion",
          "description": "Consultez les paramètres du serveur, du client et des transports."
        },
        {
          "title": "Comparer les solutions",
          "description": "Choisissez selon votre réseau, vos applications et l'entretien souhaité."
        }
      ]
    },
    "cta": {
      "title": "Créez votre propre connexion.",
      "description": "Commencez avec un serveur et une application, puis suivez le guide pas à pas."
    },
    "footer": {
      "description": "Un proxy open source à héberger vous-même.",
      "project": "Projet",
      "resources": "Ressources",
      "legal": "Pour la confidentialité et l'accès à un Internet ouvert, dans le respect des lois applicables.",
      "license": "Publié sous licence MIT."
    },
    "download": {
      "eyebrow": "Téléchargement et installation",
      "title": "Obtenir Umbra",
      "description": "Un programme, deux modes : client et serveur. Choisissez un fichier publié pour votre plateforme et votre architecture, ou compilez les sources.",
      "alpha": "Préversion Alpha. Suivez le démarrage rapide pour configurer les deux extrémités.",
      "platform": "Plateforme",
      "architecture": "Architecture",
      "releases": "Voir les téléchargements",
      "source": "Compiler les sources",
      "sourceDescription": "Vous souhaitez compiler le programme ou explorer son fonctionnement ? Clonez le dépôt. Utilisez la même version aux deux extrémités.",
      "verify": "Avant de télécharger",
      "verifyDescription": "Choisissez une version sur la page officielle et consultez les informations de vérification fournies. Les plateformes disponibles figurent dans les fichiers de cette version.",
      "requirements": "Utilisez la chaîne Rust du dépôt, actuellement 1.96.1.",
      "read": "Voir les étapes d'installation"
    },
    "protocol": {
      "eyebrow": "Fonctionnement",
      "title": "Comprenez la connexion.\nChoisissez votre configuration.",
      "description": "Umbra réunit couverture web, authentification et plusieurs transports. Adaptez la connexion à votre réseau et à vos applications tout en gardant un seul proxy local.",
      "steps": [
        {
          "title": "Un véritable site comme couverture",
          "description": "Les clients authentifiés accèdent au proxy ; les autres connexions vont au site configuré. L'identité par clés évite le renouvellement d'un certificat public pour le nœud."
        },
        {
          "title": "Réduire les opérations répétées",
          "description": "Le multiplexage TCP partage les connexions. Vision dédié transmet les données HTTPS admissibles déjà chiffrées, avec moins de chiffrement externe."
        },
        {
          "title": "Séparer les chemins TCP et UDP",
          "description": "Choisissez deux transports derrière une seule entrée SOCKS5. QUIC nécessite un chemin UDP disponible et un site de couverture compatible."
        }
      ],
      "implementation": "Choisir selon vos besoins",
      "implementationDescription": "Comparez l'entretien, le trajet des requêtes et les clients compatibles. Xray désigne ici VLESS + REALITY + Vision sur TCP.",
      "strengthsLabel": "Pour quel usage ?",
      "limitsLabel": "À prévoir",
      "layers": [
        {
          "title": "Umbra",
          "description": "Une paire client/serveur avec couverture web, TCP et QUIC.",
          "strengths": [
            "Gérer les deux extrémités et raccorder les applications à une entrée unique."
          ],
          "limits": [
            "CLI Alpha ; versions compatibles requises des deux côtés."
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "REALITY et Vision au sein de Xray.",
          "strengths": [
            "Configurer protocoles, transports et routage dans Xray."
          ],
          "limits": [
            "Faire correspondre configuration, flow et client."
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "Un protocole chiffré avec plusieurs transports possibles.",
          "strengths": [
            "Utiliser des applications déjà compatibles VMess."
          ],
          "limits": [
            "Vérifier version du client et combinaison de transport."
          ]
        },
        {
          "title": "Trojan",
          "description": "Un proxy TLS avec repli vers un site web.",
          "strengths": [
            "Déployer un service TLS classique."
          ],
          "limits": [
            "Domaine et certificat généralement nécessaires ; UDP passe par TCP."
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "Un proxy chiffré configuré par clés.",
          "strengths": [
            "Configurer un proxy TCP/UDP à l'aide d'une clé."
          ],
          "limits": [
            "Couverture web et plugins supplémentaires à configurer séparément."
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "QUIC avec datagrammes non fiables pour UDP.",
          "strengths": [
            "Utiliser QUIC et évaluer des applications UDP temps réel."
          ],
          "limits": [
            "Accès UDP et configuration TLS nécessaires."
          ]
        }
      ],
      "caveat": "Les transports suivent votre configuration. Les guides détaillent les étapes et les conditions de chaque mode.",
      "read": "Lire la comparaison complète"
    },
    "security": {
      "eyebrow": "Utiliser Umbra en sécurité",
      "title": "Maîtrisez la connexion.\nProtégez votre installation.",
      "description": "Quelques réglages concrets aident à protéger les clés, limiter les accès et entretenir le déploiement.",
      "principles": [
        {
          "title": "Protéger les clés",
          "description": "Conservez les clés privées sur le serveur. Transmettez la configuration par un canal de confiance et limitez les droits de lecture."
        },
        {
          "title": "Réserver le proxy à cet appareil",
          "description": "Écoutez sur 127.0.0.1:1080 comme dans les exemples. Configurez un contrôle d'accès avant d'ouvrir aux autres appareils."
        },
        {
          "title": "Continuer à utiliser HTTPS",
          "description": "Gardez le chiffrement entre l'application et le site. Vision transmet les données déjà chiffrées admissibles en réduisant les traitements externes répétés."
        },
        {
          "title": "Mettre les deux côtés à jour",
          "description": "Lisez les notes, gardez programme et configuration fonctionnels, et actualisez les deux extrémités lorsque le protocole change."
        }
      ],
      "limitsTitle": "Comprendre la protection",
      "limits": [
        "Version : Umbra est en Alpha, sans preuve publique d'un audit indépendant achevé.",
        "Réseau : les connexions ordinaires reçoivent un site réel ; adresses, horaires et caractéristiques du trafic restent observables.",
        "Appareils et services : protégez séparément appareils, comptes et destinations, et conservez HTTPS.",
        "Navigateur : le profil actuel repose sur Chrome 150. Le modèle de sécurité précise sa portée."
      ],
      "disclosure": "Signaler un problème de sécurité",
      "disclosureDescription": "Consultez les moyens de signalement sur la page de sécurité du dépôt. Retirez les identifiants et les détails sensibles des discussions publiques.",
      "source": "Consulter les consignes de signalement",
      "read": "Lire le modèle de sécurité"
    },
    "changelog": {
      "eyebrow": "Nouveautés",
      "title": "Découvrez les changements.\nPréparez la mise à jour.",
      "description": "Retrouvez les améliorations et les étapes pour mettre à jour le client et le serveur.",
      "prerelease": "Préversion",
      "heading": "Meilleure gestion des connexions partagées et d'UDP",
      "summary": "Cette version améliore le chiffrement, l'ordonnancement et la réception QUIC, en conservant TCP/Vision et QUIC UDP dans un seul processus.",
      "changes": [
        "Moins d'initialisations répétées : contextes TLS réutilisables et accélération cryptographique sur le matériel compatible.",
        "Traitement des flux prêts : ordonnancement selon les données disponibles et fenêtres initiales agrandies dans le budget mémoire.",
        "Gestion UDP améliorée : réception QUIC par lots et progression séparée des lectures et écritures ; BBR reste le choix par défaut.",
        "Diagnostic facilité : observations numériques facultatives, sans adresses de destination ni identifiants."
      ],
      "upgrade": "Actualisez les deux extrémités pour le mux adaptatif. Sauvegardez programmes et configuration, puis vérifiez la mise à jour avec le guide.",
      "read": "Voir cette mise à jour",
      "externalRead": "Ouvrir la version sur GitHub",
      "upgradeRead": "Lire le guide de mise à jour",
      "sourceRead": "Présentation du projet",
      "performanceRead": "Performances et configuration",
      "back": "Toutes les nouveautés"
    }
  },
  "es": {
    "nav": {
      "docs": "Documentación",
      "protocol": "Cómo funciona",
      "download": "Descargar",
      "security": "Seguridad",
      "changelog": "Novedades",
      "github": "GitHub"
    },
    "ui": {
      "language": "Idioma",
      "theme": "Cambiar tema",
      "menu": "Abrir navegación",
      "skip": "Ir al contenido",
      "copy": "Copiar comandos",
      "copied": "Copiado",
      "copyFailed": "No se pudo copiar. Selecciona los comandos y cópialos manualmente.",
      "close": "Cerrar",
      "copyCode": "Copiar código",
      "copyLink": "Copiar enlace"
    },
    "pages": {
      "download": {
        "title": "Consigue Umbra",
        "description": "Un programa con modos cliente y servidor. Elige un archivo publicado para tu plataforma y arquitectura, o compílalo desde el código fuente."
      },
      "protocol": {
        "title": "Entiende la conexión. Elige tu configuración.",
        "description": "Umbra combina cobertura web, autenticación y varios transportes. Adapta la conexión a tu red y aplicaciones manteniendo un solo proxy local."
      },
      "security": {
        "title": "Controla tu conexión. Protege tu configuración.",
        "description": "Unos ajustes concretos ayudan a proteger claves, limitar accesos y mantener el despliegue."
      },
      "changelog": {
        "title": "Descubre los cambios. Prepara la actualización.",
        "description": "Consulta las mejoras y los pasos para actualizar cliente y servidor."
      },
      "home": {
        "title": "Tu conexión. Tú decides.",
        "description": "Umbra es un proxy de código abierto que alojas tú. Conecta a través de tu servidor, usa un sitio web real como cobertura y reúne tus aplicaciones en un único proxy local."
      }
    },
    "hero": {
      "badge": "Ya disponible: 1.0.0-alpha",
      "title": "Tu conexión.",
      "accent": "Tú decides.",
      "description": "Umbra es un proxy de código abierto que alojas tú. Conecta a través de tu servidor, usa un sitio web real como cobertura y reúne tus aplicaciones en un único proxy local.",
      "start": "Inicio rápido",
      "explore": "Cómo funciona",
      "footnote": "Licencia MIT · Alojamiento propio · Versión Alpha"
    },
    "diagram": {
      "client": "Tu dispositivo",
      "transport": "Conexión proxy",
      "internet": "Internet",
      "cover": "Sitio de cobertura",
      "authenticated": "Cliente verificado",
      "fallback": "Otras conexiones → sitio web",
      "caption": "Los clientes verificados usan el proxy; las demás conexiones reciben la respuesta del sitio real."
    },
    "facts": [
      "Cobertura con un sitio real",
      "Elige el transporte",
      "Conecta tus aplicaciones",
      "Abierto y autogestionado"
    ],
    "principles": {
      "eyebrow": "Por qué Umbra",
      "title": "Gestiona tu conexión.\nConserva tus herramientas.",
      "description": "Cobertura web, transportes flexibles y un proxy local, reunidos para facilitar la configuración y el uso de tu propio servidor.",
      "features": [
        {
          "title": "Un sitio real en la misma entrada",
          "description": "Tu cliente se autentica para usar el proxy. Las demás conexiones se envían al sitio configurado y reciben su respuesta habitual."
        },
        {
          "title": "Conexiones inspiradas en Chrome",
          "description": "Umbra utiliza perfiles de negociación de Chrome para dar forma al inicio de la conexión, incorporando características habituales de la navegación web."
        },
        {
          "title": "Menos certificados que mantener",
          "description": "Las claves verifican la identidad, sin solicitar ni renovar un certificado de una CA pública para el nodo Umbra."
        },
        {
          "title": "Una entrada para tus aplicaciones",
          "description": "Conecta aplicaciones SOCKS5 o conserva la interfaz y las reglas de tu cliente compatible con Clash. Umbra gestiona la conexión remota."
        }
      ]
    },
    "start": {
      "eyebrow": "Tu primera conexión",
      "title": "Configura ambos extremos.\nConecta una aplicación.",
      "description": "Descarga la versión adecuada, genera claves y configura cliente y servidor. El inicio rápido te guía hasta la primera solicitud por SOCKS5.",
      "link": "Seguir la guía",
      "terminal": "Compilar desde el código fuente"
    },
    "docs": {
      "eyebrow": "Documentación",
      "title": "De la primera conexión a tu configuración.",
      "description": "Encuentra la guía para lo que quieres hacer ahora.",
      "cards": [
        {
          "title": "Conoce Umbra",
          "description": "Descubre qué hace y qué necesitas para empezar."
        },
        {
          "title": "Configura la conexión",
          "description": "Consulta parámetros del servidor, del cliente y del transporte."
        },
        {
          "title": "Compara soluciones",
          "description": "Elige según la red, las aplicaciones y el mantenimiento que quieres asumir."
        }
      ]
    },
    "cta": {
      "title": "Haz tuya la conexión.",
      "description": "Empieza con un servidor y una aplicación, y sigue la guía paso a paso."
    },
    "footer": {
      "description": "Un proxy de código abierto que alojas tú.",
      "project": "Proyecto",
      "resources": "Recursos",
      "legal": "Para la privacidad y el acceso a una Internet abierta, respetando la legislación aplicable.",
      "license": "Publicado bajo la licencia MIT."
    },
    "download": {
      "eyebrow": "Descarga e instalación",
      "title": "Consigue Umbra",
      "description": "Un programa con modos cliente y servidor. Elige un archivo publicado para tu plataforma y arquitectura, o compílalo desde el código fuente.",
      "alpha": "Versión preliminar Alpha. Sigue el inicio rápido para configurar ambos extremos.",
      "platform": "Plataforma",
      "architecture": "Arquitectura",
      "releases": "Ver descargas",
      "source": "Compilar desde el código fuente",
      "sourceDescription": "¿Quieres compilarlo o explorar cómo funciona? Clona el repositorio. Usa la misma versión en ambos extremos.",
      "verify": "Antes de descargar",
      "verifyDescription": "Elige una versión en la página oficial y consulta la información de verificación. Los archivos de esa versión indican las plataformas disponibles.",
      "requirements": "Usa la versión de Rust fijada en el repositorio, actualmente 1.96.1.",
      "read": "Ver pasos de instalación"
    },
    "protocol": {
      "eyebrow": "Cómo funciona",
      "title": "Entiende la conexión.\nElige tu configuración.",
      "description": "Umbra combina cobertura web, autenticación y varios transportes. Adapta la conexión a tu red y aplicaciones manteniendo un solo proxy local.",
      "steps": [
        {
          "title": "Un sitio real como cobertura",
          "description": "Los clientes verificados acceden al proxy; las demás conexiones van al sitio configurado. La identidad mediante claves evita renovar certificados públicos del nodo."
        },
        {
          "title": "Reducir trabajo repetido",
          "description": "La multiplexación TCP comparte conexiones. Vision dedicado reenvía datos HTTPS aptos ya cifrados, reduciendo el cifrado externo."
        },
        {
          "title": "Rutas distintas para TCP y UDP",
          "description": "Elige transportes diferentes detrás de un SOCKS5. QUIC necesita una ruta UDP disponible y un sitio de cobertura compatible."
        }
      ],
      "implementation": "Elige según tus necesidades",
      "implementationDescription": "Compara mantenimiento, rutas y clientes compatibles. Xray se refiere aquí a VLESS + REALITY + Vision por TCP.",
      "strengthsLabel": "Para qué sirve",
      "limitsLabel": "Qué necesitas",
      "layers": [
        {
          "title": "Umbra",
          "description": "Cliente y servidor con cobertura web, TCP y QUIC.",
          "strengths": [
            "Gestionar ambos extremos y conectar aplicaciones a una entrada."
          ],
          "limits": [
            "CLI Alpha; usa versiones compatibles en ambos extremos."
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "REALITY y Vision dentro de Xray.",
          "strengths": [
            "Configurar protocolos, transportes y rutas en Xray."
          ],
          "limits": [
            "La configuración, el flow y el cliente deben coincidir."
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "Protocolo cifrado con varias opciones de transporte.",
          "strengths": [
            "Usar aplicaciones que ya admiten VMess."
          ],
          "limits": [
            "Comprueba versión del cliente y combinación de transporte."
          ]
        },
        {
          "title": "Trojan",
          "description": "Proxy TLS con retorno a un sitio web.",
          "strengths": [
            "Desplegar un servicio TLS convencional."
          ],
          "limits": [
            "Suele requerir dominio y certificado; UDP viaja por TCP."
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "Proxy cifrado mediante claves.",
          "strengths": [
            "Configurar proxy TCP/UDP con una clave."
          ],
          "limits": [
            "La cobertura web y los complementos se configuran aparte."
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "QUIC con datagramas no fiables para UDP.",
          "strengths": [
            "Usar QUIC y evaluar aplicaciones UDP en tiempo real."
          ],
          "limits": [
            "Requiere acceso UDP y configuración TLS."
          ]
        }
      ],
      "caveat": "Los transportes siguen tu configuración. Las guías explican los pasos y requisitos de cada modo.",
      "read": "Leer la comparación completa"
    },
    "security": {
      "eyebrow": "Usar Umbra con seguridad",
      "title": "Controla tu conexión.\nProtege tu configuración.",
      "description": "Unos ajustes concretos ayudan a proteger claves, limitar accesos y mantener el despliegue.",
      "principles": [
        {
          "title": "Protege las claves",
          "description": "Guarda claves privadas solo en el servidor. Comparte la configuración por un canal de confianza y limita permisos de lectura."
        },
        {
          "title": "Mantén local el proxy",
          "description": "Escucha en 127.0.0.1:1080 como en los ejemplos. Define controles de acceso antes de permitir otros dispositivos."
        },
        {
          "title": "Sigue usando HTTPS",
          "description": "Mantén el cifrado entre la aplicación y el sitio. Vision reenvía datos ya cifrados cuando corresponde y reduce trabajo externo repetido."
        },
        {
          "title": "Actualiza ambos extremos",
          "description": "Lee las notas, conserva programa y configuración que funcionen y actualiza ambos extremos si cambia el protocolo."
        }
      ],
      "limitsTitle": "Entiende la protección",
      "limits": [
        "Versión: Umbra está en Alpha, sin evidencia pública de una auditoría independiente terminada.",
        "Red: las conexiones ordinarias reciben un sitio real; direcciones, tiempos y patrones de tráfico siguen siendo observables.",
        "Dispositivos y servicios: protege por separado equipos, cuentas y destinos, y mantén HTTPS.",
        "Navegador: el perfil actual se basa en Chrome 150. El modelo de seguridad explica su alcance."
      ],
      "disclosure": "Informar de un problema de seguridad",
      "disclosureDescription": "Consulta las vías de aviso en la página de seguridad del repositorio. Retira credenciales y detalles sensibles de las conversaciones públicas.",
      "source": "Ver cómo informar",
      "read": "Leer el modelo de seguridad"
    },
    "changelog": {
      "eyebrow": "Novedades",
      "title": "Descubre los cambios.\nPrepara la actualización.",
      "description": "Consulta las mejoras y los pasos para actualizar cliente y servidor.",
      "prerelease": "Versión preliminar",
      "heading": "Mejor gestión de conexiones compartidas y UDP",
      "summary": "Esta versión mejora cifrado, planificación y recepción QUIC, manteniendo TCP/Vision y QUIC UDP en una sola instancia.",
      "changes": [
        "Menos inicializaciones repetidas: contextos TLS reutilizables y aceleración criptográfica en hardware compatible.",
        "Trabajo donde hay datos listos: planificación de flujos activos y ventanas iniciales mayores dentro del presupuesto de memoria.",
        "Mejor gestión UDP: recepción QUIC por lotes y avance independiente de lecturas y escrituras; BBR sigue siendo el predeterminado.",
        "Diagnóstico más sencillo: observaciones numéricas opcionales sin direcciones de destino ni credenciales."
      ],
      "upgrade": "Actualiza ambos extremos para usar mux adaptativo. Guarda programas y configuración, y verifica la actualización con la guía.",
      "read": "Ver esta actualización",
      "externalRead": "Abrir versión en GitHub",
      "upgradeRead": "Leer la guía de actualización",
      "sourceRead": "Descripción del proyecto",
      "performanceRead": "Rendimiento y configuración",
      "back": "Todas las novedades"
    }
  },
  "ja": {
    "nav": {
      "docs": "ドキュメント",
      "protocol": "仕組み",
      "download": "ダウンロード",
      "security": "セキュリティ",
      "changelog": "更新情報",
      "github": "GitHub"
    },
    "ui": {
      "language": "言語",
      "theme": "表示テーマを切り替える",
      "menu": "ナビゲーションを開く",
      "skip": "本文へ移動",
      "copy": "コマンドをコピー",
      "copied": "コピーしました",
      "copyFailed": "コピーできませんでした。コマンドを選択して手動でコピーしてください。",
      "close": "閉じる",
      "copyCode": "コードをコピー",
      "copyLink": "リンクをコピー"
    },
    "pages": {
      "download": {
        "title": "Umbra を入手",
        "description": "一つの実行ファイルにクライアントとサーバーのモードを用意しています。OS と CPU に合う配布ファイルを選ぶか、ソースからビルドしてください。"
      },
      "protocol": {
        "title": "接続の仕組みを知り、 自分に合う設定を。",
        "description": "Umbra はサイトによるカバー、認証、複数の通信方式を組み合わせます。一つのローカルプロキシを維持しながら、ネットワークとアプリに合わせて選べます。"
      },
      "security": {
        "title": "接続を管理し、 設定から守る。",
        "description": "鍵の保管、アクセス制限、更新の手順を確認し、自分の環境で安全に運用しましょう。"
      },
      "changelog": {
        "title": "変更を知り、 次の更新に備える。",
        "description": "各版の改善内容と、クライアント・サーバー更新時の準備を確認できます。"
      },
      "home": {
        "title": "自分の接続を、 自分の手で。",
        "description": "Umbra は、自分のサーバーで運用するオープンソースのプロキシです。実在するサイトをカバーとして使い、一つのローカルプロキシから、いつものアプリをインターネットにつなげます。"
      }
    },
    "hero": {
      "badge": "1.0.0-alpha 公開中",
      "title": "自分の接続を、",
      "accent": "自分の手で。",
      "description": "Umbra は、自分のサーバーで運用するオープンソースのプロキシです。実在するサイトをカバーとして使い、一つのローカルプロキシから、いつものアプリをインターネットにつなげます。",
      "start": "クイックスタート",
      "explore": "仕組みを見る",
      "footnote": "MIT ライセンス · セルフホスト · Alpha 版"
    },
    "diagram": {
      "client": "手元の端末",
      "transport": "プロキシ接続",
      "internet": "インターネット",
      "cover": "カバーサイト",
      "authenticated": "認証済みクライアント",
      "fallback": "その他の接続 → Web サイト",
      "caption": "認証済みクライアントはプロキシへ、それ以外の接続には実在するサイトが応答します。"
    },
    "facts": [
      "実在サイトによるカバー",
      "通信方式を選択",
      "いつものアプリに接続",
      "オープンソースで自主運用"
    ],
    "principles": {
      "eyebrow": "Umbra を選ぶ理由",
      "title": "接続は自分で管理。\nツールは使い慣れたまま。",
      "description": "サイトによるカバー、選べる通信方式、ローカルプロキシをまとめ、自分で構築するプロキシを使いやすくします。",
      "features": [
        {
          "title": "同じ入口に実在するサイトを",
          "description": "クライアントは認証後にプロキシへ接続します。それ以外のアクセスは設定したサイトへ転送され、通常の Web サイトの応答を受け取ります。"
        },
        {
          "title": "Chrome の接続方式を参考に",
          "description": "Chrome のハンドシェイクプロファイルに基づいて接続開始時の情報を構成し、普段の Web 閲覧で使われる特徴を取り入れています。"
        },
        {
          "title": "ノード用証明書の更新を省略",
          "description": "接続相手を鍵で確認するため、Umbra ノード用に公開 CA 証明書を取得したり更新したりする必要がありません。"
        },
        {
          "title": "一つの入口でアプリに接続",
          "description": "SOCKS5 対応アプリを直接接続できます。Clash 系クライアントの画面とルールを維持し、リモート接続を Umbra に任せることもできます。"
        }
      ]
    },
    "start": {
      "eyebrow": "最初の接続へ",
      "title": "両端を設定して、\nアプリをつなぐ。",
      "description": "端末に合う版を取得し、鍵を生成してサーバーとクライアントを設定します。クイックスタートで SOCKS5 経由の最初の接続まで進めます。",
      "link": "ガイドに沿って始める",
      "terminal": "ソースからビルド"
    },
    "docs": {
      "eyebrow": "ドキュメント",
      "title": "最初の接続から、自分に合う設定まで。",
      "description": "今やりたいことに合うガイドを見つけてください。",
      "cards": [
        {
          "title": "Umbra とは",
          "description": "できることと、使い始めるための準備を確認します。"
        },
        {
          "title": "接続を設定する",
          "description": "両端の設定項目を確認し、通信方式を選びます。"
        },
        {
          "title": "プロキシ構成を比較",
          "description": "ネットワーク、管理方法、アプリに合う構成を考えます。"
        }
      ]
    },
    "cta": {
      "title": "自分の接続を始めよう。",
      "description": "一台のサーバーと一つのアプリから、ガイドに沿って接続を確認しましょう。"
    },
    "footer": {
      "description": "自分のサーバーで運用するオープンソースのプロキシ。",
      "project": "プロジェクト",
      "resources": "関連情報",
      "legal": "プライバシー保護と開かれたインターネットへのアクセスに。適用される法律に従ってご利用ください。",
      "license": "MIT ライセンスで公開。"
    },
    "download": {
      "eyebrow": "ダウンロードとインストール",
      "title": "Umbra を入手",
      "description": "一つの実行ファイルにクライアントとサーバーのモードを用意しています。OS と CPU に合う配布ファイルを選ぶか、ソースからビルドしてください。",
      "alpha": "Alpha プレリリースです。初回はクイックスタートに沿って両端を設定してください。",
      "platform": "OS",
      "architecture": "アーキテクチャ",
      "releases": "配布ファイルを見る",
      "source": "ソースからビルド",
      "sourceDescription": "自分でビルドしたい場合や実装を調べたい場合は、リポジトリを取得してください。両端で同じバージョンを使います。",
      "verify": "ダウンロード前の確認",
      "verifyDescription": "公式リリースページで版を選び、公開されている検証情報を確認してください。対応ファイルは各リリースに掲載されています。",
      "requirements": "リポジトリ指定の Rust ツールチェーンを使用します。現在は 1.96.1 です。",
      "read": "インストール手順を見る"
    },
    "protocol": {
      "eyebrow": "仕組み",
      "title": "接続の仕組みを知り、\n自分に合う設定を。",
      "description": "Umbra はサイトによるカバー、認証、複数の通信方式を組み合わせます。一つのローカルプロキシを維持しながら、ネットワークとアプリに合わせて選べます。",
      "steps": [
        {
          "title": "実在するサイトで入口をカバー",
          "description": "認証済みクライアントはプロキシへ、他の接続は設定したサイトへ転送します。鍵による認証でノードの公開 CA 証明書管理を省けます。"
        },
        {
          "title": "接続と暗号化の重複を減らす",
          "description": "TCP 多重化では接続を共有します。独立 Vision では対象の暗号化済み HTTPS データを転送し、外側の暗号化を減らします。"
        },
        {
          "title": "TCP と UDP に別々の経路を",
          "description": "一つの SOCKS5 で異なる通信方式を使えます。QUIC には到達可能な UDP 経路と対応カバーサイトが必要です。"
        }
      ],
      "implementation": "使い方に合わせて比較",
      "implementationDescription": "管理する項目、通信経路、対応クライアントで選びます。ここでの Xray は TCP 上の VLESS + REALITY + Vision です。",
      "strengthsLabel": "向いている用途",
      "limitsLabel": "利用前の確認",
      "layers": [
        {
          "title": "Umbra",
          "description": "サイトによるカバー、TCP、QUIC をまとめたクライアントとサーバー。",
          "strengths": [
            "両端を自分で管理し、一つの入口にアプリを接続する。"
          ],
          "limits": [
            "現在は Alpha の CLI。両端のバージョンを合わせます。"
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "Xray 上で REALITY と Vision を組み合わせる構成。",
          "strengths": [
            "Xray でプロトコル、通信方式、ルーティングを設定する。"
          ],
          "limits": [
            "コア設定、flow、クライアントの対応を確認します。"
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "複数の通信方式と組み合わせられる暗号化プロトコル。",
          "strengths": [
            "すでに VMess に対応するアプリを利用する。"
          ],
          "limits": [
            "クライアントの版と通信構成を確認します。"
          ]
        },
        {
          "title": "Trojan",
          "description": "TLS を利用し、未認証接続をサイトに転送するプロキシ。",
          "strengths": [
            "通常の TLS サービスとして構築する。"
          ],
          "limits": [
            "一般的にドメインと証明書を管理し、UDP は TCP 上で運びます。"
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "鍵で設定する暗号化プロキシ。",
          "strengths": [
            "鍵を使って TCP/UDP プロキシを構築する。"
          ],
          "limits": [
            "サイトによるカバーや追加プラグインは別途設定します。"
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "QUIC を使い、UDP を非信頼性データグラムで運ぶ方式。",
          "strengths": [
            "QUIC を利用し、リアルタイム UDP アプリを評価する。"
          ],
          "limits": [
            "UDP が通るネットワークと TLS 設定が必要です。"
          ]
        }
      ],
      "caveat": "通信方式は設定に従います。各モードの手順と利用条件はガイドで確認できます。",
      "read": "詳しい比較を読む"
    },
    "security": {
      "eyebrow": "安全に使う",
      "title": "接続を管理し、\n設定から守る。",
      "description": "鍵の保管、アクセス制限、更新の手順を確認し、自分の環境で安全に運用しましょう。",
      "principles": [
        {
          "title": "鍵を安全に保管",
          "description": "秘密鍵はサーバーだけに保存します。クライアント設定は信頼できる経路で渡し、読み取り権限を制限します。"
        },
        {
          "title": "ローカルプロキシは端末内に",
          "description": "例のとおり 127.0.0.1:1080 で待ち受けます。他の端末へ公開する前にアクセス制御を設定します。"
        },
        {
          "title": "HTTPS を引き続き利用",
          "description": "アプリとサイト間の暗号化を維持します。Vision は条件に合う暗号化済みデータを転送し、外側の重複処理を減らします。"
        },
        {
          "title": "両端の版を合わせる",
          "description": "リリースノートを読み、動作する実行ファイルと設定を保存します。プロトコルが変わる場合は両端を更新します。"
        }
      ],
      "limitsTitle": "保護される範囲を知る",
      "limits": [
        "開発段階：現在は Alpha 版で、独立した安全性監査の完了を示す公開資料はありません。",
        "ネットワーク：通常のアクセスには実在サイトが応答します。アドレス、時刻、通信パターンは観測される可能性があります。",
        "端末とサービス：端末、アカウント、接続先の安全は個別に管理し、HTTPS を使い続けてください。",
        "ブラウザー：現在のプロファイルは Chrome 150 に基づきます。対象範囲はセキュリティモデルで説明しています。"
      ],
      "disclosure": "セキュリティ上の問題を報告",
      "disclosureDescription": "リポジトリのセキュリティページで報告方法を確認してください。公開の相談では認証情報や機微な構成を除いてください。",
      "source": "報告方法を見る",
      "read": "セキュリティモデルを読む"
    },
    "changelog": {
      "eyebrow": "更新情報",
      "title": "変更を知り、\n次の更新に備える。",
      "description": "各版の改善内容と、クライアント・サーバー更新時の準備を確認できます。",
      "prerelease": "プレリリース",
      "heading": "共有接続と UDP 処理を改善",
      "summary": "暗号化、共有接続のスケジューリング、QUIC 受信を改善しました。一つのインスタンスで TCP/Vision と QUIC UDP を利用できます。",
      "changes": [
        "初期化の重複を削減：TLS 暗号コンテキストを再利用し、対応ハードウェアで暗号処理を高速化します。",
        "準備の整ったストリームを処理：読み書き可能な流れを処理し、予算内で初期ウィンドウを拡大します。",
        "UDP 処理を改善：QUIC をバッチ受信し、UDP の読み書きを独立して進めます。既定の輻輳制御は BBR です。",
        "調査を容易に：任意の数値診断で通信状態を確認でき、宛先アドレスや認証情報は出力しません。"
      ],
      "upgrade": "適応型 mux には両端の更新が必要です。実行ファイルと設定を保存し、更新ガイドで接続を確認してください。",
      "read": "今回の更新を見る",
      "externalRead": "GitHub のリリースを見る",
      "upgradeRead": "更新ガイドを読む",
      "sourceRead": "プロジェクト概要",
      "performanceRead": "性能と設定の説明",
      "back": "すべての更新"
    }
  },
  "ca": {
    "nav": {
      "docs": "Documentació",
      "protocol": "Com funciona",
      "download": "Descarrega",
      "security": "Seguretat",
      "changelog": "Novetats",
      "github": "GitHub"
    },
    "ui": {
      "language": "Llengua",
      "theme": "Canvia el tema",
      "menu": "Obre la navegació",
      "skip": "Ves al contingut",
      "copy": "Copia les ordres",
      "copied": "Copiat",
      "copyFailed": "No s'ha pogut copiar. Selecciona les ordres i copia-les manualment.",
      "close": "Tanca",
      "copyCode": "Copia el codi",
      "copyLink": "Copia l'enllaç"
    },
    "pages": {
      "download": {
        "title": "Aconsegueix Umbra",
        "description": "Un programa amb modes client i servidor. Tria un fitxer publicat per a la teva plataforma i arquitectura, o compila'l des del codi font."
      },
      "protocol": {
        "title": "Entén la connexió. Tria la configuració.",
        "description": "Umbra combina cobertura web, autenticació i diversos transports. Adapta la connexió a la xarxa i les aplicacions amb una sola entrada local."
      },
      "security": {
        "title": "Controla la connexió. Protegeix la configuració.",
        "description": "Uns ajustos concrets ajuden a protegir claus, limitar accessos i mantenir el desplegament."
      },
      "changelog": {
        "title": "Descobreix els canvis. Prepara l'actualització.",
        "description": "Consulta les millores i els passos per actualitzar client i servidor."
      },
      "home": {
        "title": "La teva connexió. Tu decideixes.",
        "description": "Umbra és un servidor intermediari de codi obert que allotges tu mateix. Connecta't a través del teu servidor, utilitza un lloc web real com a cobertura i reuneix les aplicacions en una sola entrada local."
      }
    },
    "hero": {
      "badge": "Ja disponible: 1.0.0-alpha",
      "title": "La teva connexió.",
      "accent": "Tu decideixes.",
      "description": "Umbra és un servidor intermediari de codi obert que allotges tu mateix. Connecta't a través del teu servidor, utilitza un lloc web real com a cobertura i reuneix les aplicacions en una sola entrada local.",
      "start": "Inici ràpid",
      "explore": "Com funciona",
      "footnote": "Llicència MIT · Allotjament propi · Versió Alpha"
    },
    "diagram": {
      "client": "El teu dispositiu",
      "transport": "Connexió intermediària",
      "internet": "Internet",
      "cover": "Lloc de cobertura",
      "authenticated": "Client verificat",
      "fallback": "Altres connexions → lloc web",
      "caption": "Els clients verificats utilitzen el servei intermediari; les altres connexions reben la resposta del lloc real."
    },
    "facts": [
      "Cobertura amb un lloc real",
      "Tria el transport",
      "Connecta les aplicacions",
      "Obert i autogestionat"
    ],
    "principles": {
      "eyebrow": "Per què Umbra?",
      "title": "Gestiona la connexió.\nConserva les eines.",
      "description": "Cobertura web, transports flexibles i una entrada local, reunits per facilitar la configuració i l'ús del teu servidor.",
      "features": [
        {
          "title": "Un lloc real a la mateixa entrada",
          "description": "El teu client s'autentica per connectar-se. Les altres connexions s'envien al lloc configurat i en reben la resposta habitual."
        },
        {
          "title": "Connexions inspirades en Chrome",
          "description": "Umbra utilitza perfils de negociació de Chrome per donar forma a l'inici de la connexió, incorporant característiques habituals de la navegació web."
        },
        {
          "title": "Menys certificats per mantenir",
          "description": "Les claus verifiquen la identitat, sense haver de sol·licitar ni renovar un certificat d'una CA pública per al node Umbra."
        },
        {
          "title": "Una entrada per a les aplicacions",
          "description": "Connecta aplicacions SOCKS5 o conserva la interfície i les regles del client compatible amb Clash. Umbra gestiona la connexió remota."
        }
      ]
    },
    "start": {
      "eyebrow": "La primera connexió",
      "title": "Configura els dos extrems.\nConnecta una aplicació.",
      "description": "Descarrega la versió adequada, genera claus i configura client i servidor. L'inici ràpid et guia fins a la primera petició per SOCKS5.",
      "link": "Segueix la guia",
      "terminal": "Compila el codi font"
    },
    "docs": {
      "eyebrow": "Documentació",
      "title": "De la primera connexió a la teva configuració.",
      "description": "Troba la guia per al que vols fer ara.",
      "cards": [
        {
          "title": "Coneix Umbra",
          "description": "Descobreix què fa i què necessites per començar."
        },
        {
          "title": "Configura la connexió",
          "description": "Consulta paràmetres de servidor, client i transport."
        },
        {
          "title": "Compara solucions",
          "description": "Tria segons la xarxa, les aplicacions i el manteniment que vols assumir."
        }
      ]
    },
    "cta": {
      "title": "Fes teva la connexió.",
      "description": "Comença amb un servidor i una aplicació, i segueix la guia pas a pas."
    },
    "footer": {
      "description": "Un servidor intermediari de codi obert que allotges tu mateix.",
      "project": "Projecte",
      "resources": "Recursos",
      "legal": "Per a la privadesa i l'accés a una Internet oberta, respectant la legislació aplicable.",
      "license": "Publicat amb llicència MIT."
    },
    "download": {
      "eyebrow": "Descàrrega i instal·lació",
      "title": "Aconsegueix Umbra",
      "description": "Un programa amb modes client i servidor. Tria un fitxer publicat per a la teva plataforma i arquitectura, o compila'l des del codi font.",
      "alpha": "Versió preliminar Alpha. Segueix l'inici ràpid per configurar els dos extrems.",
      "platform": "Plataforma",
      "architecture": "Arquitectura",
      "releases": "Veu les descàrregues",
      "source": "Compila el codi font",
      "sourceDescription": "Vols compilar-lo o explorar-ne el funcionament? Clona el repositori. Fes servir la mateixa versió als dos extrems.",
      "verify": "Abans de descarregar",
      "verifyDescription": "Tria una versió a la pàgina oficial i consulta'n la informació de verificació. Els fitxers de cada versió indiquen les plataformes disponibles.",
      "requirements": "Utilitza la versió de Rust fixada al repositori, actualment 1.96.1.",
      "read": "Veu els passos d'instal·lació"
    },
    "protocol": {
      "eyebrow": "Com funciona",
      "title": "Entén la connexió.\nTria la configuració.",
      "description": "Umbra combina cobertura web, autenticació i diversos transports. Adapta la connexió a la xarxa i les aplicacions amb una sola entrada local.",
      "steps": [
        {
          "title": "Un lloc real com a cobertura",
          "description": "Els clients verificats entren al servei intermediari; els altres van al lloc configurat. La identitat amb claus evita renovar certificats públics del node."
        },
        {
          "title": "Reduir feina repetida",
          "description": "La multiplexació TCP comparteix connexions. Vision dedicat reenvia dades HTTPS aptes ja xifrades, reduint el xifratge extern."
        },
        {
          "title": "Rutes diferents per a TCP i UDP",
          "description": "Tria transports diferents darrere d'un SOCKS5. QUIC necessita una ruta UDP disponible i un lloc de cobertura compatible."
        }
      ],
      "implementation": "Tria segons les necessitats",
      "implementationDescription": "Compara manteniment, rutes i clients compatibles. Xray es refereix aquí a VLESS + REALITY + Vision per TCP.",
      "strengthsLabel": "Per a què serveix",
      "limitsLabel": "Què necessites",
      "layers": [
        {
          "title": "Umbra",
          "description": "Client i servidor amb cobertura web, TCP i QUIC.",
          "strengths": [
            "Gestionar els dos extrems i connectar aplicacions a una entrada."
          ],
          "limits": [
            "CLI Alpha; utilitza versions compatibles als dos extrems."
          ]
        },
        {
          "title": "Xray + VLESS + REALITY + Vision",
          "description": "REALITY i Vision dins de Xray.",
          "strengths": [
            "Configurar protocols, transports i rutes a Xray."
          ],
          "limits": [
            "Configuració, flow i client han de coincidir."
          ]
        },
        {
          "title": "VMess AEAD",
          "description": "Protocol xifrat amb diverses opcions de transport.",
          "strengths": [
            "Utilitzar aplicacions que ja admeten VMess."
          ],
          "limits": [
            "Comprova la versió del client i la combinació de transport."
          ]
        },
        {
          "title": "Trojan",
          "description": "Servei intermediari TLS amb retorn a un lloc web.",
          "strengths": [
            "Desplegar un servei TLS convencional."
          ],
          "limits": [
            "Sol requerir domini i certificat; UDP viatja per TCP."
          ]
        },
        {
          "title": "Shadowsocks",
          "description": "Servei intermediari xifrat amb claus.",
          "strengths": [
            "Configurar TCP/UDP amb una clau."
          ],
          "limits": [
            "La cobertura web i els connectors es configuren a part."
          ]
        },
        {
          "title": "Hysteria 2",
          "description": "QUIC amb datagrames no fiables per a UDP.",
          "strengths": [
            "Utilitzar QUIC i avaluar aplicacions UDP en temps real."
          ],
          "limits": [
            "Requereix accés UDP i configuració TLS."
          ]
        }
      ],
      "caveat": "Els transports segueixen la configuració. Les guies expliquen els passos i els requisits de cada mode.",
      "read": "Llegeix la comparació completa"
    },
    "security": {
      "eyebrow": "Utilitzar Umbra amb seguretat",
      "title": "Controla la connexió.\nProtegeix la configuració.",
      "description": "Uns ajustos concrets ajuden a protegir claus, limitar accessos i mantenir el desplegament.",
      "principles": [
        {
          "title": "Protegeix les claus",
          "description": "Desa les claus privades només al servidor. Comparteix la configuració per un canal de confiança i limita els permisos de lectura."
        },
        {
          "title": "Mantén l'accés local",
          "description": "Escolta a 127.0.0.1:1080 com als exemples. Defineix controls d'accés abans de permetre altres dispositius."
        },
        {
          "title": "Continua utilitzant HTTPS",
          "description": "Mantén el xifratge entre l'aplicació i el lloc. Vision reenvia dades ja xifrades quan correspon i redueix feina externa repetida."
        },
        {
          "title": "Actualitza els dos extrems",
          "description": "Llegeix les notes, conserva programa i configuració funcionals i actualitza els dos extrems si canvia el protocol."
        }
      ],
      "limitsTitle": "Entén la protecció",
      "limits": [
        "Versió: Umbra és en fase Alpha, sense evidència pública d'una auditoria independent acabada.",
        "Xarxa: les connexions ordinàries reben un lloc real; adreces, temps i patrons de trànsit continuen sent observables.",
        "Dispositius i serveis: protegeix equips, comptes i destinacions per separat, i mantén HTTPS.",
        "Navegador: el perfil actual es basa en Chrome 150. El model de seguretat n'explica l'abast."
      ],
      "disclosure": "Informar d'un problema de seguretat",
      "disclosureDescription": "Consulta les vies d'avís a la pàgina de seguretat del repositori. Retira credencials i detalls sensibles de les converses públiques.",
      "source": "Veu com informar-ne",
      "read": "Llegeix el model de seguretat"
    },
    "changelog": {
      "eyebrow": "Novetats",
      "title": "Descobreix els canvis.\nPrepara l'actualització.",
      "description": "Consulta les millores i els passos per actualitzar client i servidor.",
      "prerelease": "Versió preliminar",
      "heading": "Millor gestió de connexions compartides i UDP",
      "summary": "Aquesta versió millora xifratge, planificació i recepció QUIC, mantenint TCP/Vision i QUIC UDP en una sola instància.",
      "changes": [
        "Menys inicialitzacions repetides: contextos TLS reutilitzables i acceleració criptogràfica en maquinari compatible.",
        "Feina on hi ha dades disponibles: planificació de fluxos actius i finestres inicials més grans dins del pressupost de memòria.",
        "Millor gestió UDP: recepció QUIC per lots i avanç independent de lectures i escriptures; BBR continua sent el predeterminat.",
        "Diagnòstic més senzill: observacions numèriques opcionals sense adreces de destinació ni credencials."
      ],
      "upgrade": "Actualitza els dos extrems per al mux adaptatiu. Desa programes i configuració, i verifica l'actualització amb la guia.",
      "read": "Veu aquesta actualització",
      "externalRead": "Obre la versió a GitHub",
      "upgradeRead": "Llegeix la guia d'actualització",
      "sourceRead": "Descripció del projecte",
      "performanceRead": "Rendiment i configuració",
      "back": "Totes les novetats"
    }
  }
};

export const marketingResources = Object.fromEntries(
  Object.entries(marketingCopy).map(([locale, copy]) => [locale, { marketing: copy }]),
) as Record<Locale, { marketing: MarketingCopy }>;
