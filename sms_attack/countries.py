"""国际区号 -> 中文国家名, for the 'IP国家 vs 手机号国家' consistency metric (David #8/#9).

Region codes come from the `phonenumbers` library (authoritative), the Chinese names
from the table below, so the mapping is not hand-guessed per country code.
"""
import phonenumbers

REGION_ZH = {
    "US": "美国", "CA": "加拿大", "CN": "中国", "RU": "俄罗斯", "KZ": "哈萨克斯坦",
    "EG": "埃及", "NL": "荷兰", "FR": "法国", "ES": "西班牙", "IT": "意大利",
    "RO": "罗马尼亚", "AT": "奥地利", "GB": "英国", "DE": "德国", "MX": "墨西哥",
    "BR": "巴西", "MY": "马来西亚", "ID": "印度尼西亚", "PH": "菲律宾", "SG": "新加坡",
    "KR": "韩国", "IN": "印度", "PK": "巴基斯坦", "MM": "缅甸", "MA": "摩洛哥",
    "DZ": "阿尔及利亚", "GM": "冈比亚", "SN": "塞内加尔", "ML": "马里", "SL": "塞拉利昂",
    "GH": "加纳", "CM": "喀麦隆", "AO": "安哥拉", "SD": "苏丹", "ET": "埃塞俄比亚",
    "KE": "肯尼亚", "MZ": "莫桑比克", "ZM": "赞比亚", "MG": "马达加斯加", "ZW": "津巴布韦",
    "NA": "纳米比亚", "MW": "马拉维", "LS": "莱索托", "LU": "卢森堡", "EE": "爱沙尼亚",
    "AM": "亚美尼亚", "BY": "白俄罗斯", "UA": "乌克兰", "SI": "斯洛文尼亚", "HN": "洪都拉斯",
    "EC": "厄瓜多尔", "UY": "乌拉圭", "HK": "中国香港", "KH": "柬埔寨", "BD": "孟加拉国",
    "TW": "中国台湾", "LB": "黎巴嫩", "SY": "叙利亚", "IL": "以色列", "MN": "蒙古",
    "TJ": "塔吉克斯坦", "AZ": "阿塞拜疆", "UZ": "乌兹别克斯坦", "TR": "土耳其",
    "TH": "泰国", "VN": "越南", "JP": "日本", "AU": "澳大利亚", "NG": "尼日利亚",
    "ZA": "南非", "PL": "波兰", "PT": "葡萄牙", "BE": "比利时", "CH": "瑞士",
    "SE": "瑞典", "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IE": "爱尔兰",
    "CZ": "捷克", "GR": "希腊", "HU": "匈牙利", "BG": "保加利亚", "RS": "塞尔维亚",
    "HR": "克罗地亚", "SK": "斯洛伐克", "LT": "立陶宛", "LV": "拉脱维亚", "MD": "摩尔多瓦",
    "GE": "格鲁吉亚", "AE": "阿联酋", "SA": "沙特阿拉伯", "IQ": "伊拉克", "IR": "伊朗",
    "JO": "约旦", "KW": "科威特", "QA": "卡塔尔", "OM": "阿曼", "YE": "也门",
    "AF": "阿富汗", "NP": "尼泊尔", "LK": "斯里兰卡", "KG": "吉尔吉斯斯坦",
    "TM": "土库曼斯坦", "TZ": "坦桑尼亚", "UG": "乌干达", "RW": "卢旺达", "CI": "科特迪瓦",
    "BF": "布基纳法索", "NE": "尼日尔", "TD": "乍得", "SO": "索马里", "LY": "利比亚",
    "TN": "突尼斯", "BJ": "贝宁", "TG": "多哥", "GN": "几内亚", "LR": "利比里亚",
    "CD": "刚果金", "CG": "刚果布", "GA": "加蓬", "BW": "博茨瓦纳", "SZ": "斯威士兰",
    "NZ": "新西兰", "CL": "智利", "AR": "阿根廷", "CO": "哥伦比亚", "PE": "秘鲁",
    "VE": "委内瑞拉", "BO": "玻利维亚", "PY": "巴拉圭", "GT": "危地马拉",
    "SV": "萨尔瓦多", "NI": "尼加拉瓜", "CR": "哥斯达黎加", "PA": "巴拿马",
    "DO": "多米尼加", "CU": "古巴", "JM": "牙买加", "HT": "海地",
}

_cache = {}


def cc_to_zh(cc):
    """'92' -> '巴基斯坦'. Returns None when the code has no single region."""
    if cc in _cache:
        return _cache[cc]
    try:
        region = phonenumbers.region_code_for_country_code(int(cc))
    except (TypeError, ValueError):
        region = None
    name = REGION_ZH.get(region) if region and region != "ZZ" else None
    _cache[cc] = name
    return name


def cc_to_region(cc):
    try:
        r = phonenumbers.region_code_for_country_code(int(cc))
        return None if r == "ZZ" else r
    except (TypeError, ValueError):
        return None
