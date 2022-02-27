#include "filter.hh"
#include "archive_io.hh"

#include <fnmatch.h>
#include <string.h>

namespace pkgfile {
namespace filter {

bool Directory::Matches(std::string_view line) const {
  return !line.empty() && line.back() == '/';
}

bool Bin::Matches(std::string_view line) const {
  if (directory_filter_.Matches(line)) {
    return false;
  }

  return line.find("/bin/") != line.npos || line.find("/sbin/") != line.npos;
}

Glob::Glob(std::string glob_pattern, bool case_sensitive)
    : glob_pattern_(std::move(glob_pattern)), flags_(FNM_PATHNAME) {
  if (case_sensitive) {
    flags_ |= FNM_CASEFOLD;
  }
}

bool Glob::Matches(std::string_view line) const {
  return fnmatch(glob_pattern_.c_str(), std::string(line).c_str(), flags_) == 0;
}

Regex::~Regex() {
  pcre_free_study(re_extra_);
  pcre_free(re_);
}

// static
std::unique_ptr<Regex> Regex::Compile(const std::string& pattern,
                                      bool case_sensitive) {
  const int options = case_sensitive ? 0 : PCRE_CASELESS;
  const char* err;
  int offset;

  pcre* re = pcre_compile(pattern.c_str(), options, &err, &offset, nullptr);
  if (re == nullptr) {
    fprintf(stderr, "error: failed to compile regex at char %d: %s\n", offset,
            err);
    return nullptr;
  }

  pcre_extra* re_extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &err);
  if (err) {
    fprintf(stderr, "error: failed to study regex: %s\n", err);
    pcre_free(re);
    return nullptr;
  }

  return std::make_unique<Regex>(re, re_extra);
}

bool Regex::Matches(std::string_view line) const {
  return pcre_exec(re_, re_extra_, line.data(), line.size(), 0,
                   PCRE_NO_UTF16_CHECK, nullptr, 0) >= 0;
}

Exact::Exact(std::string match, bool case_sensitive) {
  if (case_sensitive) {
    predicate_ = [m = std::move(match)](std::string_view line) {
      return m == line;
    };
  } else {
    predicate_ = [m = std::move(match)](std::string_view line) {
      if (line.size() != m.size()) {
        return false;
      }

      return strncasecmp(line.data(), m.data(), m.size()) == 0;
    };
  }
}

bool Exact::Matches(std::string_view line) const { return predicate_(line); }

Basename::Basename(std::string match, bool case_sensitive)
    : predicate_(std::make_unique<Exact>(match, case_sensitive)), case_sensitive_(case_sensitive), match_(match) {}

bool Basename::Matches(std::string_view line) const {
  const auto pos = line.rfind('/');
  if (pos != line.npos) {
    line.remove_prefix(pos + 1);
  }

  return predicate_->Matches(line);
}

static uint64_t fnv_hash(const std::string& str) {
  uint64_t h = 0xcbf29ce484222325;
  for(unsigned char c : str) {
    h = (h * 0x100000001B3) ^ c;
  }
  return h;
}

static uint64_t read_u64(int fd) {
  uint64_t buf = 0;
  // TODO: figure out a nice way to do error checking here
  read(fd, &buf, 8);
  return buf;
}
static uint64_t read_u64_at(int fd, uint64_t off) {
  lseek(fd, off, SEEK_SET);
  return read_u64(fd);
}

std::optional<std::vector<uint64_t>> Basename::GetIndexOffsets(const std::filesystem::path repo) const {
  // index is case-sensitive only
  if(!case_sensitive_) return std::nullopt;
  auto index_path = repo;
  index_path.replace_extension("basename_index");
  auto file = ReadOnlyFile::Open(index_path);
  if (file == nullptr)
    return std::nullopt;
  int fd = file->fd();

  uint64_t target_hash = fnv_hash(match_);
  // index file format:
  // u64 nb (number of basenames in cache)
  // nb times: u64 hash, u64 offset
  // where offset is either 2**63 + archive_index
  // or an offset into the index file itself, where it represents a list of archive indices
  uint64_t num_basenames = read_u64(fd);
  uint64_t lo = 0, hi = num_basenames;
  uint64_t mid_val;
  while(lo <= hi) {
    uint64_t mid = (lo+hi)/2;
    mid_val = read_u64_at(fd, 16*mid+8);
    if(mid_val < target_hash) {
      lo = mid+1;
    } else if(mid_val > target_hash) {
      hi = mid-1;
    } else {
      break;
    }
  }

  if(mid_val != target_hash)
    return std::vector<uint64_t>();

  uint64_t offset = read_u64(fd);
  const uint64_t MASK = 1ULL << 63;
  if(offset & MASK) {
    std::vector<uint64_t> res = { offset & (MASK-1) };
    return res;
  } else {
    std::vector<uint64_t> res;
    uint64_t val = read_u64_at(fd, offset);
    res.push_back(val & (MASK-1));
    while((val & MASK) == 0ULL) {
      val = read_u64(fd);
      res.push_back(val & (MASK-1));
    }
    return res;
  }
}

std::optional<std::vector<uint64_t>> And::GetIndexOffsets(const std::filesystem::path repo) const {
	auto lhs_o = lhs_->GetIndexOffsets(repo);
	auto rhs_o = rhs_->GetIndexOffsets(repo);
	if(!lhs_o) return rhs_o;
	if(!rhs_o) return lhs_o;
  // merging the 2 lists is somewhat nontrivial, and we never do And on 2
  // indexable filters anyways, so just disable indexing in this case
  return std::nullopt;
}

}  // namespace filter
}  // namespace pkgfile
