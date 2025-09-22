import type { NewsEnrichment, NewsArticle, PressRelease, NewsSentiment } from '../../types/enrichment';

export interface NewsAPIResponse {
  status: string;
  totalResults: number;
  articles: Array<{
    source: {
      id: string;
      name: string;
    };
    author: string;
    title: string;
    description: string;
    url: string;
    urlToImage: string;
    publishedAt: string;
    content: string;
  }>;
}

export interface GoogleNewsResponse {
  kind: string;
  items: Array<{
    title: string;
    link: string;
    snippet: string;
    pagemap?: {
      newsarticle?: Array<{
        headline: string;
        datepublished: string;
        author: string;
      }>;
    };
  }>;
}

export // TODO: Consider splitting NewsService into smaller, focused classes
class NewsService {
  private newsApiKey: string;
  private googleApiKey: string;
  private serpApiKey: string;

  constructor(config: {
    newsApiKey: string;
    googleApiKey: string;
    serpApiKey: string;
  }) {
    this.newsApiKey = config.newsApiKey;
    this.googleApiKey = config.googleApiKey;
    this.serpApiKey = config.serpApiKey;
  }

  async enrichWithNews(companyName: string, domain?: string): Promise<{
    news: NewsEnrichment | null;
    error?: string;
  }> {
    try {
      const [generalNews, fundingNews, productNews] = await Promise.all([
        this.getGeneralNews(companyName),
        this.getFundingNews(companyName),
        this.getProductNews(companyName, domain)
      ]);

      const allArticles = [
        ...generalNews,
        ...fundingNews,
        ...productNews
      ];

      if (allArticles.length === 0) {
        return { news: null };
      }

      const sentiment = await this.analyzeSentiment(allArticles);

      const news: NewsEnrichment = {
        recent_news: generalNews,
        funding_announcements: this.extractFundingNews(fundingNews),
        product_launches: this.extractProductNews(productNews),
        sentiment_analysis: sentiment
      };

      return { news };
    } catch (error) {
      return {
        news: null,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async getGeneralNews(companyName: string): Promise<NewsArticle[]> {
    try {
      // Use NewsAPI for general news
      const response = await fetch(
        `https://newsapi.org/v2/everything?q="${companyName}"&sortBy=publishedAt&pageSize=10&apiKey=${this.newsApiKey}`
      );

      if (!response.ok) {
        return [];
      }

      const data: NewsAPIResponse = await response.json();

      return data.articles.map(article => ({
        title: article.title,
        url: article.url,
        source: article.source.name,
        published_date: article.publishedAt,
        summary: article.description || article.content?.substring(0, 200) || '',
        sentiment: 'neutral' as const,
        relevance_score: this.calculateRelevance(article.title + ' ' + article.description, companyName),
        topics: this.extractTopics(article.title + ' ' + article.description)
      }));
    } catch (error) {
      return [];
    }
  }

  private async getFundingNews(companyName: string): Promise<NewsArticle[]> {
    try {
      const fundingKeywords = ['funding', 'raised', 'investment', 'round', 'venture', 'series'];
      const query = `"${companyName}" AND (${fundingKeywords.join(' OR ')})`;

      const response = await fetch(
        `https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&sortBy=publishedAt&pageSize=5&apiKey=${this.newsApiKey}`
      );

      if (!response.ok) {
        return [];
      }

      const data: NewsAPIResponse = await response.json();

      return data.articles.map(article => ({
        title: article.title,
        url: article.url,
        source: article.source.name,
        published_date: article.publishedAt,
        summary: article.description || '',
        sentiment: 'positive' as const, // Funding news is typically positive
        relevance_score: this.calculateRelevance(article.title + ' ' + article.description, companyName),
        topics: ['funding', ...this.extractTopics(article.title + ' ' + article.description)]
      }));
    } catch (error) {
      return [];
    }
  }

  private async getProductNews(companyName: string, domain?: string): Promise<NewsArticle[]> {
    try {
      const productKeywords = ['launch', 'product', 'feature', 'release', 'announcement', 'unveils'];
      const query = `"${companyName}" AND (${productKeywords.join(' OR ')})`;

      const response = await fetch(
        `https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&sortBy=publishedAt&pageSize=5&apiKey=${this.newsApiKey}`
      );

      if (!response.ok) {
        return [];
      }

      const data: NewsAPIResponse = await response.json();

      return data.articles.map(article => ({
        title: article.title,
        url: article.url,
        source: article.source.name,
        published_date: article.publishedAt,
        summary: article.description || '',
        sentiment: this.detectSentiment(article.title + ' ' + article.description),
        relevance_score: this.calculateRelevance(article.title + ' ' + article.description, companyName),
        topics: ['product', ...this.extractTopics(article.title + ' ' + article.description)]
      }));
    } catch (error) {
      return [];
    }
  }

  private async searchGoogleNews(query: string): Promise<NewsArticle[]> {
    try {
      const response = await fetch(
        `https://www.googleapis.com/customsearch/v1?key=${this.googleApiKey}&cx=your_search_engine_id&q=${encodeURIComponent(query)}&tbm=nws&num=10`
      );

      if (!response.ok) {
        return [];
      }

      const data: GoogleNewsResponse = await response.json();

      return data.items?.map(item => ({
        title: item.title,
        url: item.link,
        source: 'Google News',
        published_date: item.pagemap?.newsarticle?.[0]?.datepublished || new Date().toISOString(),
        summary: item.snippet,
        sentiment: this.detectSentiment(item.title + ' ' + item.snippet),
        relevance_score: this.calculateRelevance(item.title + ' ' + item.snippet, query),
        topics: this.extractTopics(item.title + ' ' + item.snippet)
      })) || [];
    } catch (error) {
      return [];
    }
  }

  private async analyzeSentiment(articles: NewsArticle[]): Promise<NewsSentiment> {
    if (articles.length === 0) {
      return {
        overall_sentiment: 'neutral',
        sentiment_score: 0,
        trending: 'stable',
        key_themes: []
      };
    }

    // Calculate sentiment scores
    const sentimentCounts = { positive: 0, neutral: 0, negative: 0 };
    let totalScore = 0;

    articles.forEach(article => {
      sentimentCounts[article.sentiment]++;
      totalScore += this.getSentimentScore(article.sentiment);
    });

    const avgScore = totalScore / articles.length;
    const overallSentiment = this.getOverallSentiment(sentimentCounts);

    // Extract key themes
    const allTopics = articles.flatMap(article => article.topics);
    const topicCounts = allTopics.reduce((acc, topic) => {
      acc[topic] = (acc[topic] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const keyThemes = Object.entries(topicCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([topic]) => topic);

    // Determine trending direction based on recent vs older articles
    const recentArticles = articles.filter(article =>
      new Date(article.published_date) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    );
    const olderArticles = articles.filter(article =>
      new Date(article.published_date) <= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    );

    const recentAvgScore = recentArticles.length > 0
      ? recentArticles.reduce((sum,
  article) => sum + this.getSentimentScore(article.sentiment), 0) / recentArticles.length
      : 0;
    const olderAvgScore = olderArticles.length > 0
      ? olderArticles.reduce((sum,
  article) => sum + this.getSentimentScore(article.sentiment), 0) / olderArticles.length
      : 0;

    let trending: 'up' | 'stable' | 'down' = 'stable';
    if (recentAvgScore > olderAvgScore + 0.1) trending = 'up';
    else if (recentAvgScore < olderAvgScore - 0.1) trending = 'down';

    return {
      overall_sentiment: overallSentiment,
      sentiment_score: avgScore,
      trending,
      key_themes: keyThemes
    };
  }

  private extractFundingNews(articles: NewsArticle[]): any[] {
    return articles
      .filter(article => article.topics.includes('funding'))
      .map(article => ({
        amount: this.extractFundingAmount(article.title + ' ' + article.summary),
        round_type: this.extractRoundType(article.title + ' ' + article.summary),
        date: article.published_date,
        investors: this.extractInvestors(article.title + ' ' + article.summary),
        source: article.source,
        url: article.url
      }));
  }

  private extractProductNews(articles: NewsArticle[]): any[] {
    return articles
      .filter(article => article.topics.includes('product'))
      .map(article => ({
        product_name: this.extractProductName(article.title),
        launch_date: article.published_date,
        description: article.summary,
        market_impact: this.assessMarketImpact(article.title + ' ' + article.summary),
        url: article.url
      }));
  }

  private calculateRelevance(text: string, companyName: string): number {
    const lowerText = text.toLowerCase();
    const lowerCompany = companyName.toLowerCase();

    let score = 0;

    // Exact company name match
    if (lowerText.includes(lowerCompany)) score += 0.8;

    // Company name in quotes
    if (lowerText.includes(`"${lowerCompany}"`)) score += 0.2;

    // Title vs content weight
    const titleWeight = 0.7;
    const contentWeight = 0.3;

    return Math.min(score, 1.0);
  }

  private extractTopics(text: string): string[] {
    const topicKeywords = {
      'funding': ['funding', 'raised', 'investment', 'round', 'venture', 'series'],
      'product': ['launch', 'product', 'feature', 'release', 'announcement', 'unveils'],
      'acquisition': ['acquired', 'acquisition', 'merger', 'bought', 'purchase'],
      'partnership': ['partnership', 'partner', 'collaboration', 'alliance'],
      'expansion': ['expansion', 'expand', 'international', 'new market'],
      'hiring': ['hires', 'hiring', 'joins', 'appointed', 'new', 'ceo', 'cto'],
      'financial': ['revenue', 'profit', 'earnings', 'quarterly', 'financial'],
      'regulatory': ['regulation', 'compliance', 'legal', 'lawsuit', 'fine'],
      'technology': ['ai', 'machine learning', 'blockchain', 'cloud', 'api']
    };

    const lowerText = text.toLowerCase();
    const topics: string[] = [];

    for (const [topic, keywords] of Object.entries(topicKeywords)) {
      if (keywords.some(keyword => lowerText.includes(keyword))) {
        topics.push(topic);
      }
    }

    return topics;
  }

  private detectSentiment(text: string): 'positive' | 'neutral' | 'negative' {
    const positiveWords =
  ['success', 'growth', 'launch', 'innovation', 'award', 'partnership', 'expansion', 'breakthrough'];
    const negativeWords = ['lawsuit', 'fine', 'decline', 'loss', 'problem', 'issue', 'controversy', 'scandal'];

    const lowerText = text.toLowerCase();
    const positiveCount = positiveWords.filter(word => lowerText.includes(word)).length;
    const negativeCount = negativeWords.filter(word => lowerText.includes(word)).length;

    if (positiveCount > negativeCount) return 'positive';
    if (negativeCount > positiveCount) return 'negative';
    return 'neutral';
  }

  private getSentimentScore(sentiment: 'positive' | 'neutral' | 'negative'): number {
    switch (sentiment) {
      case 'positive': return 1;
      case 'neutral': return 0;
      case 'negative': return -1;
    }
  }

  private getOverallSentiment(counts: Record<string, number>): 'positive' | 'neutral' | 'negative' {
    const { positive, neutral, negative } = counts;
    const total = positive + neutral + negative;

    if (positive / total > 0.5) return 'positive';
    if (negative / total > 0.5) return 'negative';
    return 'neutral';
  }

  private extractFundingAmount(text: string): number {
    const amountPattern = /\$([0-9]+(?:\.[0-9]+)?)\s*(million|billion|M|B)/i;
    const match = text.match(amountPattern);

    if (match) {
      const amount = parseFloat(match[1]);
      const unit = match[2].toLowerCase();

      if (unit.startsWith('b')) return amount * 1000000000;
      if (unit.startsWith('m')) return amount * 1000000;
    }

    return 0;
  }

  private extractRoundType(text: string): string {
    const roundTypes = ['seed', 'series a', 'series b', 'series c', 'series d', 'ipo', 'acquisition'];
    const lowerText = text.toLowerCase();

    for (const type of roundTypes) {
      if (lowerText.includes(type)) {
        return type;
      }
    }

    return 'unknown';
  }

  private extractInvestors(text: string): string[] {
    // Simple extraction - in practice, would use NER or more sophisticated parsing
    const investorPattern = /([A-Z][a-z]+ (?:Capital|Ventures|Partners|Fund|Investments?))/g;
    const matches = text.match(investorPattern);
    return matches || [];
  }

  private extractProductName(title: string): string {
    // Extract potential product names from title
    const productPattern = /(launches|unveils|announces|releases)\s+([A-Z][A-Za-z\s]+)/i;
    const match = title.match(productPattern);
    return match ? match[2].trim() : 'Unknown Product';
  }

  private assessMarketImpact(text: string): 'low' | 'medium' | 'high' {
    const highImpactWords = ['revolutionary', 'breakthrough', 'game-changing', 'first-ever', 'industry-leading'];
    const mediumImpactWords = ['significant', 'important', 'major', 'notable', 'substantial'];

    const lowerText = text.toLowerCase();

    if (highImpactWords.some(word => lowerText.includes(word))) return 'high';
    if (mediumImpactWords.some(word => lowerText.includes(word))) return 'medium';
    return 'low';
  }
}